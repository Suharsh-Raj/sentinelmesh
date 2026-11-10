"""Durable, forward-only Gmail sync. MailAgent handles imported queue rows."""
import time
from datetime import datetime, timezone
from threading import Event

from sqlalchemy import select, update
from sqlalchemy.dialects.sqlite import insert

from .email_link_scans import enqueue_email_links
from .gmail_mime import parse_message
from .gmail_oauth import GmailError, SavedAuthorization, read_config
from .models import Email, GmailSyncState, now_utc

INCLUDED = {"INBOX", "SPAM"}
EXCLUDED = {"DRAFT", "TRASH"}
POLL_SECONDS = 15


class SyncStopped(Exception):
    pass


def valid_cursor(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 40:
        raise GmailError("api_error", "Gmail did not return a valid history cursor.")
    return value


def valid_id(value):
    if not isinstance(value, str) or not value or len(value) > 255:
        raise GmailError("api_error", "Gmail did not return a valid message ID.")
    return value


def snapshot_label(message, cutoff_ms):
    labels = message.get("labelIds", [])
    if not isinstance(labels, list):
        raise GmailError("api_error", "Gmail returned invalid message labels.")
    labels = set(labels)
    if not (labels & INCLUDED) or labels & EXCLUDED:
        return None
    try:
        received_ms = int(message["internalDate"])
        seconds, milliseconds = divmod(received_ms, 1000)
        received = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=milliseconds * 1000)
    except (KeyError, ValueError, TypeError, OverflowError, OSError):
        raise GmailError("api_error", "Gmail returned an invalid received time. The sync cursor was kept.") from None
    return ("Spam" if "SPAM" in labels else "Inbox", received) if received_ms >= cutoff_ms else None


def connect(sessions, config, client, clock_ms=lambda: time.time_ns() // 1_000_000):
    """Verify the account before any listing/fetch, and bind the DB once."""
    with sessions() as db:
        state = db.get(GmailSyncState, 1)
        if state and state.account_key != config.account_key:
            raise GmailError("account_mismatch", "This local Gmail database belongs to a different account.")
    # Capture the boundary just before the first successful profile request.
    # The initial bounded scan covers arrivals during that request.
    cutoff_ms = clock_ms()
    profile = client.profile(config.account)
    anchor = valid_cursor(profile.get("historyId"))
    with sessions.begin() as db:
        db.execute(insert(GmailSyncState).values(id=1, account_key=config.account_key, cutoff_ms=cutoff_ms)
                   .on_conflict_do_nothing(index_elements=["id"]))
        state = db.get(GmailSyncState, 1)
        if state.account_key != config.account_key:
            raise GmailError("account_mismatch", "This local Gmail database belongs to a different account.")
        return state.cutoff_ms, state.history_id, anchor


class GmailSync:
    def __init__(self, sessions, config_loader=read_config, authorization=None, clock_ms=lambda: time.time_ns() // 1_000_000):
        self.sessions = sessions
        self.config_loader = config_loader
        self.authorization = authorization if authorization is not None else SavedAuthorization()
        self.clock_ms = clock_ms
        self.stop = Event()
        self.status = {"state": "connecting", "error": None}
        self.transient_failures = 0

    def describe(self):
        with self.sessions() as db:
            state = db.get(GmailSyncState, 1)
            last = state.last_success if state else None
        return {**self.status, "last_success": last.replace(tzinfo=timezone.utc).isoformat() if last else None}

    def check_stop(self):
        if self.stop.is_set():
            raise SyncStopped

    def pages(self, client, path, query):
        seen = set()
        while True:
            self.check_stop()
            page = client.get(path, query)
            yield page
            token = page.get("nextPageToken")
            if not token:
                break
            if not isinstance(token, str) or token in seen:
                raise GmailError("api_error", "Gmail returned an invalid continuation token. The sync cursor was kept.")
            seen.add(token)
            query = {**query, "pageToken": token}

    def import_message(self, client, key, cutoff_ms, message_id):
        self.check_stop()
        with self.sessions() as db:
            existing = db.scalar(select(Email.id).where(
                Email.source == "gmail", Email.account_key == key, Email.external_message_id == message_id,
            ))
            if existing is not None:
                return

        def text_part(attachment_id, limit):
            self.check_stop()
            try:
                return client.text_part(message_id, valid_id(attachment_id), limit).get("data")
            except GmailError as exc:
                if exc.code == 404:
                    # If the message is gone, the second 404 reaches the outer
                    # handler; a missing part alone is marked on the message.
                    client.message(message_id)
                    return None
                if exc.code == 413:
                    return None
                raise

        try:
            metadata = client.message(message_id)
            location = snapshot_label(metadata, cutoff_ms)
            if location is None:
                return
            header_only = False
            try:
                self.check_stop()
                message = client.message(message_id, full=True)
                location = snapshot_label(message, cutoff_ms)
                if location is None:
                    return
            except GmailError as exc:
                if exc.code != 413:
                    raise
                message, header_only = metadata, True
            fields = parse_message(message.get("payload", {}), text_part, header_only=header_only)
        except GmailError as exc:
            if exc.code == 404:
                return  # Deleted before retrieval; nothing remains to import.
            raise
        label, received = location
        self.check_stop()
        with self.sessions.begin() as db:
            email_id = db.scalar(insert(Email).values(
                **fields, source="gmail", account_key=key, external_message_id=message_id,
                received_at=received, source_label=label, verdict="PENDING", risk_score=0,
                reasons=["Queued for automatic MailAgent inbox processing."], folder="Inbox",
                processed=False, revoked=False, created_at=now_utc(),
            ).on_conflict_do_nothing(
                index_elements=["source", "account_key", "external_message_id"],
            ).returning(Email.id))
            if email_id is not None:
                enqueue_email_links(db, email_id, fields["urls"])

    def bounded_resync(self, client, key, cutoff_ms):
        # Gmail's labelIds list is an AND filter, so query each separately.
        # Overlap the search window by one second; internalDate is authoritative.
        for label in ("INBOX", "SPAM"):
            for page in self.pages(client, "messages", {
                "labelIds": label, "includeSpamTrash": "true", "q": f"after:{cutoff_ms // 1000 - 1}",
                # Gmail returns HTTP 204 when an empty list has no selected fields.
                # Include the result estimate so an empty page still has a JSON body.
                "maxResults": 100, "fields": "nextPageToken,messages(id),resultSizeEstimate",
            }):
                for message in page.get("messages", []):
                    self.import_message(client, key, cutoff_ms, valid_id(message.get("id")))

    def read_history(self, client, key, cutoff_ms, cursor):
        pages = self.pages(client, "history", {
            "startHistoryId": cursor, "maxResults": 100,
            "historyTypes": ["messageAdded", "labelAdded", "labelRemoved"],
            "fields": "historyId,nextPageToken,history(messagesAdded(message(id)),labelsAdded(message(id),labelIds),labelsRemoved(message(id),labelIds))",
        })
        while True:
            # Only a history-list 404 is a cursor expiry; other failures keep
            # the old cursor and are retried from the beginning.
            try:
                page = next(pages)
            except StopIteration:
                break
            except GmailError as exc:
                if exc.code == 404:
                    return None
                raise
            for change in page.get("history", []):
                for field, relevant in (("messagesAdded", None), ("labelsAdded", INCLUDED), ("labelsRemoved", EXCLUDED)):
                    for item in change.get(field, []):
                        if relevant is None or relevant.intersection(item.get("labelIds", [])):
                            self.import_message(client, key, cutoff_ms, valid_id(item["message"].get("id")))
            if not page.get("nextPageToken"):
                checkpoint = valid_cursor(page.get("historyId"))
                if int(checkpoint) < int(cursor):
                    raise GmailError("api_error", "Gmail returned an older history cursor. The sync cursor was kept.")
                return checkpoint
        raise GmailError("api_error", "Gmail did not return a complete history response.")

    def sync_once(self):
        config = self.config_loader()
        client = self.authorization.get_client(config)
        cutoff_ms, cursor, anchor = connect(self.sessions, config, client, self.clock_ms)
        checkpoint = self.read_history(client, config.account_key, cutoff_ms, cursor) if cursor is not None else None
        if checkpoint is None:
            self.bounded_resync(client, config.account_key, cutoff_ms)
            # Snapshot the history ID before the scan, so changes during the
            # scan are replayed on the next successful poll.
            checkpoint = anchor
        self.check_stop()
        with self.sessions.begin() as db:
            db.execute(update(GmailSyncState).where(
                GmailSyncState.id == 1, GmailSyncState.account_key == config.account_key,
                GmailSyncState.history_id == cursor,
            ).values(history_id=checkpoint, last_success=now_utc()))

    def poll(self):
        """Run on a worker thread. Return an appropriate delay for the next poll."""
        try:
            self.check_stop()
            self.sync_once()
        except SyncStopped:
            return POLL_SECONDS
        except GmailError as exc:
            if exc.code == 401:
                self.authorization.invalidate()
            self.status = {"state": exc.state, "error": str(exc)}
            self.transient_failures = min(self.transient_failures + 1, 3) if exc.transient else 0
            return POLL_SECONDS * 2 ** self.transient_failures
        except Exception:
            self.status = {"state": "sync_error", "error": "Gmail sync could not finish. The app will retry without advancing the cursor."}
            return POLL_SECONDS
        self.transient_failures = 0
        self.status = {"state": "connected", "error": None}
        return POLL_SECONDS
