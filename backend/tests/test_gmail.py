import asyncio
import base64
import hashlib
import json
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend import gmail_oauth as oauth
from backend import main as api
from backend.database import ensure_schema
from backend.gmail_mime import BODY_CHARS, PART_BYTES, parse_message
from backend.gmail_oauth import Config, GmailClient, GmailError, SavedAuthorization
from backend.gmail_sync import GmailSync, connect
from backend.mail_model import MailModel
from backend.models import Email, GmailSyncState, LedgerEntry, LinkScan

CUTOFF = 1_700_000_000_500
ACCOUNT = "mailbox@example.org"


def text_data(text, charset="utf-8"):
    return base64.urlsafe_b64encode(text.encode(charset)).decode().rstrip("=")


def message(message_id, labels, received=CUTOFF + 100, sender="Jаne Test <friend@example.org>"):
    return {"id": message_id, "internalDate": str(received), "labelIds": labels, "payload": {
        "mimeType": "text/plain",
        "headers": [{"name": "From", "value": sender}, {"name": "Subject", "value": "Synthetic meeting"},
                    {"name": "Date", "value": "Thu, 01 Jan 1970 00:00:00 +0000"}],
        "body": {"data": text_data("Agenda for the meeting")},
    }}


class MockGmail:
    def __init__(self):
        self.profile = {"emailAddress": ACCOUNT, "historyId": "10"}
        self.lists = {}
        self.histories = {}
        self.messages = {}
        self.parts = {}
        self.full_errors = {}
        self.calls = []

    def __call__(self, url, *, token, limit):
        assert token == "synthetic-access-token"
        request = urlsplit(url)
        assert request.scheme == "https" and request.netloc == "gmail.googleapis.com"
        path = request.path.removeprefix("/gmail/v1/users/me/")
        query = parse_qs(request.query)
        self.calls.append((path, query))
        page = query.get("pageToken", [""])[0]
        if path == "profile":
            response = self.profile
        elif path == "messages":
            assert query["includeSpamTrash"] == ["true"]
            assert query["q"] == [f"after:{CUTOFF // 1000 - 1}"]
            assert len(query["labelIds"]) == 1
            response = self.lists.get((query["labelIds"][0], page), {})
        elif path == "history":
            response = self.histories.get((query["startHistoryId"][0], page), {"historyId": "10"})
        else:
            _, message_id, *rest = path.split("/")
            if rest:
                response = self.parts[(message_id, rest[1])]
            elif query["format"] == ["full"] and message_id in self.full_errors:
                response = self.full_errors[message_id]
            else:
                response = self.messages.get(message_id, GmailError("api_error", "gone", code=404))
        if isinstance(response, Exception):
            raise response
        return response


class GmailTests(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)
        self.engine = create_engine(f"sqlite:///{(self.path / 'gmail.db').as_posix()}")
        self.addCleanup(self.engine.dispose)
        ensure_schema(self.engine, "gmail")
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.config = Config(ACCOUNT, "synthetic-client", "synthetic-secret", self.path / "oauth-token.json")
        self.mock = MockGmail()
        self.client = GmailClient("synthetic-access-token", self.mock)
        self.authorization = Mock()
        self.authorization.get_client.return_value = self.client
        self.sync = self.make_sync()

    def make_sync(self, clock=CUTOFF):
        return GmailSync(self.sessions, lambda: self.config, self.authorization, lambda: clock)

    def state(self):
        with self.sessions() as db:
            return db.get(GmailSyncState, 1)

    def rows(self):
        with self.sessions() as db:
            return {e.external_message_id: e for e in db.scalars(select(Email))}

    def test_account_checked_before_list_or_fetch_and_db_binding(self):
        self.mock.profile["emailAddress"] = "different@example.org"
        self.assertEqual(self.sync.poll(), 15)
        self.assertEqual(self.sync.describe()["state"], "account_mismatch")
        self.assertIsNone(self.state())
        self.assertEqual([path for path, query in self.mock.calls], ["profile"])
        self.mock.profile["emailAddress"] = ACCOUNT.upper()
        self.sync.sync_once()
        self.assertEqual(self.state().cutoff_ms, CUTOFF)
        self.mock.calls.clear()
        self.config = Config("different@example.org", "synthetic-client", "synthetic-secret", self.config.token_path)
        self.sync.poll()
        self.assertEqual(self.mock.calls, [])
        self.assertEqual(self.sync.describe()["state"], "account_mismatch")

    def test_initial_cutoff_labels_pages_and_separate_received_time(self):
        self.mock.lists[("INBOX", "")] = {"messages": [{"id": "inbox"}, {"id": "old"}, {"id": "sent"}], "nextPageToken": "second"}
        self.mock.lists[("INBOX", "second")] = {"messages": [{"id": "draft"}, {"id": "trash"}, {"id": "deleted"}]}
        self.mock.lists[("SPAM", "")] = {"messages": [{"id": "spam"}]}
        for key, labels in {"inbox": ["INBOX"], "old": ["INBOX"], "sent": ["SENT"],
                            "draft": ["INBOX", "DRAFT"], "trash": ["TRASH", "SPAM"], "spam": ["SPAM"]}.items():
            self.mock.messages[key] = message(key, labels, CUTOFF - 1 if key == "old" else CUTOFF + 100)
        # Sender-controlled Date points back to 1970; the Inbox message is still new.
        self.sync.sync_once()
        self.assertEqual({key: row.source_label for key, row in self.rows().items()}, {"inbox": "Inbox", "spam": "Spam"})
        self.assertLess(self.rows()["inbox"].received_at, self.rows()["inbox"].created_at)
        self.assertEqual(self.rows()["inbox"].received_at.microsecond, 600000)
        self.assertEqual([path for path, query in self.mock.calls if query.get("format") == ["full"]],
                         ["messages/inbox", "messages/spam"])
        self.assertEqual(self.state().history_id, "10")

    def test_initial_sync_checkpoints_after_empty_spam_listing(self):
        self.mock.lists[("INBOX", "")] = {"messages": [{"id": "inbox"}]}
        self.mock.messages["inbox"] = message("inbox", ["INBOX"])
        self.authorization.get_client.return_value = GmailClient("synthetic-access-token")

        def open_response(request, *, timeout):
            token = request.get_header("Authorization").removeprefix("Bearer ")
            payload = self.mock(request.full_url, token=token, limit=None)
            path, query = self.mock.calls[-1]
            if path == "messages" and query["labelIds"] == ["SPAM"]:
                # Reproduce Gmail's empty 204 for the old field mask and
                # its JSON response when the result estimate is requested.
                if "resultSizeEstimate" not in query["fields"][0].split(","):
                    return BytesIO()
                payload = {"resultSizeEstimate": 0}
            return BytesIO(json.dumps(payload).encode())

        with patch.object(oauth, "build_opener") as opener:
            opener.return_value.open.side_effect = open_response
            self.sync.poll()

        self.assertEqual(set(self.rows()), {"inbox"})
        self.assertEqual(self.sync.describe()["state"], "connected")
        self.assertEqual(self.state().history_id, "10")
        self.assertIsNotNone(self.state().last_success)

    def test_history_retry_keeps_cursor_and_deduplicates_across_restart_and_reauth(self):
        self.sync.sync_once()
        self.mock.histories[("10", "")] = {"historyId": "20", "nextPageToken": "b", "history": [
            {"messagesAdded": [{"message": {"id": "first"}}]},
        ]}
        self.mock.histories[("10", "b")] = GmailError("retrying", "Temporary failure", transient=True)
        self.mock.messages["first"] = message("first", ["INBOX"])
        self.mock.messages["second"] = message("second", ["SPAM"])
        with patch.object(oauth.time, "sleep") as sleep:
            self.assertEqual(self.sync.poll(), 30)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])
        self.assertEqual(self.state().history_id, "10")
        self.assertEqual(set(self.rows()), {"first"})
        self.assertEqual(self.sync.describe()["state"], "retrying")
        self.mock.profile["historyId"] = "20"
        self.mock.histories[("10", "b")] = {"historyId": "20", "history": [
            {"labelsAdded": [{"message": {"id": "first"}, "labelIds": ["SPAM"]},
                             {"message": {"id": "second"}, "labelIds": ["SPAM"]}]},
        ]}
        # New auth and a fresh worker reuse the same on-disk DB.
        self.mock.messages["first"]["labelIds"] = ["SPAM"]
        self.engine.dispose()
        connect(self.sessions, self.config, self.client, lambda: CUTOFF + 99999)
        restarted = self.make_sync(CUTOFF + 99999)
        self.assertEqual(restarted.poll(), 15)
        self.mock.histories[("20", "")] = {"historyId": "20", "history": [
            {"messagesAdded": [{"message": {"id": "first"}}]},
        ]}
        restarted.sync_once()
        self.assertEqual(self.state().history_id, "20")
        self.assertEqual(self.state().cutoff_ms, CUTOFF)
        self.assertEqual({key: row.source_label for key, row in self.rows().items()}, {"first": "Inbox", "second": "Spam"})
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as db:
                db.add(Email(source="gmail", account_key=self.config.account_key, external_message_id="first",
                             sender="", subject="Test", verdict="PENDING", risk_score=0))

    def test_expired_cursor_resync_pages_without_backfill_and_handles_deleted(self):
        self.sync.sync_once()
        self.mock.histories[("10", "")] = GmailError("api_error", "expired", code=404)
        self.mock.profile["historyId"] = "88"
        self.mock.lists[("INBOX", "")] = {"nextPageToken": "second", "messages": [{"id": "old"}]}
        self.mock.lists[("INBOX", "second")] = {"messages": [{"id": "new"}, {"id": "deleted"}]}
        self.mock.messages["old"] = message("old", ["INBOX"], CUTOFF - 1)
        self.mock.messages["new"] = message("new", ["INBOX"])
        self.mock.messages["deleted"] = message("deleted", ["INBOX"])
        self.mock.full_errors["deleted"] = GmailError("api_error", "deleted", code=404)
        self.make_sync(CUTOFF + 60000).sync_once()
        self.assertEqual(set(self.rows()), {"new"})
        self.assertEqual(self.state().history_id, "88")

    def test_header_only_on_oversized_response_and_failed_part_keeps_checkpoint(self):
        self.mock.lists[("INBOX", "")] = {"messages": [{"id": "large"}, {"id": "part"}]}
        self.mock.messages["large"] = message("large", ["INBOX"])
        self.mock.messages["part"] = message("part", ["INBOX"])
        self.mock.messages["part"]["payload"]["body"] = {"size": 9, "attachmentId": "body"}
        self.mock.full_errors["large"] = GmailError("api_error", "large", code=413)
        self.mock.parts[("part", "body")] = GmailError("api_error", "forbidden", code=403)
        self.sync.poll()
        self.assertEqual(self.rows()["large"].content_limits, ["message_download_limit"])
        self.assertEqual(self.rows()["large"].body, "")
        self.assertIsNone(self.state().history_id)
        self.assertEqual(self.sync.describe()["state"], "api_error")
        self.mock.parts[("part", "body")] = {"data": text_data("body part")}
        self.sync.sync_once()
        self.assertEqual(self.state().history_id, "10")
        self.assertEqual(self.rows()["part"].body, "body part")

    def test_missing_revoked_and_expired_access_are_explicit(self):
        auth = SavedAuthorization()
        with self.assertRaisesRegex(GmailError, "not authorized"):
            auth.get_client(self.config)
        oauth.write_authorization(self.config, "synthetic-refresh-token")
        with patch.object(oauth, "request_json", side_effect=GmailError("authorization_required", "Authorization expired")):
            with self.assertRaisesRegex(GmailError, "expired"):
                auth.get_client(self.config)
        self.mock.profile = GmailError("authorization_required", "Authorization rejected", code=401)
        self.sync.poll()
        self.authorization.invalidate.assert_called_once()
        self.assertEqual(self.sync.describe()["state"], "authorization_required")
        self.assertEqual(self.rows(), {})
        self.assertIsNone(self.state())

    def test_wrong_mode_cannot_open_gmail_database_or_adopt_legacy_simulated_data(self):
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            ensure_schema(self.engine, "simulated")
        legacy = create_engine("sqlite://")
        self.addCleanup(legacy.dispose)
        ensure_schema(legacy)
        with self.assertRaisesRegex(RuntimeError, "fresh database"):
            ensure_schema(legacy, "gmail")

    def test_gmail_import_runs_rules_and_ml_and_revoke_stays_local(self):
        self.mock.lists[("SPAM", "")] = {"messages": [{"id": "new"}]}
        self.mock.messages["new"] = message("new", ["SPAM"])
        self.sync.sync_once()
        model = MailModel("ready", model_version="synthetic-model", threshold=0.2,
                          scorer=lambda subject, body: {"phishing_score": 0.05, "model_prediction": "legitimate"})
        with patch.multiple(api, SessionLocal=self.sessions, MAIL_SOURCE="gmail", gmail_sync=self.sync, mail_model=model):
            asyncio.run(api.process_pending_emails())
            email = api.get_emails()[0]
            ledger = api.get_ledger()[0]
            self.assertEqual(email["verdict"], "QUARANTINE")
            self.assertEqual(email["ml_analysis"]["model_prediction"], "legitimate")
            self.assertEqual(email["ml_analysis"], ledger["ml_analysis"])
            self.assertNotIn("account_key", email)
            self.assertEqual(api.get_stats()["mail_source"], "gmail")
            calls = len(self.mock.calls)
            asyncio.run(api.revoke(ledger["id"]))
            after = api.get_emails()[0]
            self.assertEqual(after["source_label"], "Spam")
            self.assertEqual((after["risk_score"], after["reasons"], after["ml_analysis"]),
                             (email["risk_score"], email["reasons"], email["ml_analysis"]))
            self.assertEqual(len(self.mock.calls), calls)
            self.assertEqual(api.get_ledger()[0]["status"], "REVOKED")

    def test_lifespan_no_seeds_and_demo_http_routes_refuse_mutation(self):
        async def exercise():
            with patch.multiple(api, SessionLocal=self.sessions, MAIL_SOURCE="gmail",
                                initialize_database=lambda: ensure_schema(self.engine, "gmail")):
                with patch.object(api, "GmailSync", return_value=self.sync), patch.object(api, "load_mail_model", return_value=MailModel("disabled")):
                    async with api.lifespan(api.app):
                        self.assertEqual(self.rows(), {})
                        with self.sessions() as db:
                            self.assertEqual(list(db.scalars(select(LinkScan))), [])
                        for path, payload in (("/api/reset", {}), ("/api/emails", {"sender": "demo@example.org", "subject": "test"})):
                            responses = []
                            queue = asyncio.Queue()
                            await queue.put({"type": "http.request", "body": json.dumps(payload).encode(), "more_body": False})
                            async def send(msg):
                                responses.append(msg)
                            await api.app({"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                                           "http_version": "1.1", "method": "POST", "scheme": "http", "path": path,
                                           "root_path": "", "query_string": b"", "headers": [
                                               (b"content-type", b"application/json"), (b"host", b"127.0.0.1:8000")]},
                                          queue.get, send)
                            self.assertEqual(responses[0]["status"], 403)
                        self.assertEqual(self.rows(), {})
        asyncio.run(exercise())


class MimeAndOAuthTests(unittest.TestCase):
    def test_mime_nested_plain_charset_html_urls_and_no_ordinary_attachments(self):
        fetch = Mock(return_value=text_data("Café https://example.org/body", "iso-8859-1"))
        payload = {"mimeType": "multipart/mixed", "headers": [
            {"name": "From", "value": "=?UTF-8?Q?Jos=C3=A9?= <sender@example.org>"},
            {"name": "Subject", "value": "=?UTF-8?Q?R=C3=A9union?="},
            {"name": "Reply-To", "value": "=?UTF-8?Q?Caf=C3=A9?= <reply@example.org>"},
        ], "parts": [
            {"mimeType": "multipart/alternative", "parts": [
                {"mimeType": "text/plain", "headers": [{"name": "Content-Type", "value": "text/plain; charset=iso-8859-1"}],
                 "body": {"attachmentId": "text", "size": 40}},
                {"mimeType": "text/html", "body": {"data": text_data('<p>HTML alternative</p><a href="https://example.org/a?x=1&amp;y=2">Link</a>')}},
            ]},
            {"mimeType": "text/plain", "filename": "notes.txt", "body": {"attachmentId": "file", "size": 5}},
            {"mimeType": "application/octet-stream", "body": {"attachmentId": "file2", "size": 5}},
        ]}
        result = parse_message(payload, fetch)
        self.assertEqual((result["display_name"], result["sender"], result["subject"], result["reply_to"]),
                         ("José", "sender@example.org", "Réunion", "reply@example.org"))
        self.assertEqual(result["body"], "Café https://example.org/body")
        self.assertEqual(result["urls"], ["https://example.org/body", "https://example.org/a?x=1&y=2"])
        self.assertEqual(fetch.call_args.args[0], "text")
        fetch.assert_called_once()

    def test_html_fallback_empty_and_truncated(self):
        fetch = Mock()
        result = parse_message({"mimeType": "text/html", "body": {"data": text_data(
            '<p>Hi &amp; bye</p><script>https://example.org/hidden</script>'
            '<img src="https://example.org/pixel"><a href="javascript:alert(1)">Safe text</a>')}}, fetch)
        self.assertEqual(result["subject"], "(No subject)")
        self.assertIn("Hi & bye", result["body"])
        self.assertEqual(result["urls"], [])
        self.assertEqual(parse_message({}, fetch)["body"], "")
        huge = parse_message({"mimeType": "multipart/mixed", "parts": [
            {"mimeType": "text/plain", "body": {"data": text_data("a" * (PART_BYTES + 3))}},
            {"mimeType": "text/plain", "body": {"attachmentId": "huge", "size": PART_BYTES + 1}},
        ]}, fetch)
        self.assertEqual(len(huge["body"]), BODY_CHARS)
        self.assertEqual(set(huge["content_limits"]), {"part_byte_limit", "text_part_download_limit", "body_character_limit"})
        fetch.assert_not_called()

    def test_loopback_state_pkce_exact_scope_and_no_real_google_request(self):
        observed = {}
        errors = []
        config = Config(ACCOUNT, "synthetic-client", "synthetic-secret", Path("unused.json"))

        def browser(url):
            observed.update({key: values[0] for key, values in parse_qs(urlsplit(url).query).items()})
            def callback():
                try:
                    with self.assertRaises(HTTPError) as err:
                        urlopen(observed["redirect_uri"] + "?state=wrong&code=wrong", timeout=3)
                    self.assertEqual(err.exception.code, 400)
                    params = urlencode({"state": observed["state"], "code": "synthetic-auth-code"})
                    with urlopen(observed["redirect_uri"] + "?" + params, timeout=3) as response:
                        self.assertEqual(response.status, 200)
                except Exception as exc:
                    errors.append(exc)
            observed["thread"] = Thread(target=callback)
            observed["thread"].start()
            return True

        with patch.object(oauth.webbrowser, "open", side_effect=browser), patch.object(oauth, "request_json", return_value={
            "access_token": "synthetic-access-token", "refresh_token": "synthetic-refresh-token", "scope": oauth.SCOPE,
        }) as exchange:
            _, refresh = oauth.authorize(config)
        observed["thread"].join(4)
        self.assertEqual(errors, [])
        self.assertTrue(observed["redirect_uri"].startswith("http://127.0.0.1:"))
        self.assertEqual(observed["scope"], oauth.SCOPE)
        self.assertEqual(observed["code_challenge_method"], "S256")
        self.assertEqual(refresh, "synthetic-refresh-token")
        form = exchange.call_args.kwargs["form"]
        digest = hashlib.sha256(form["code_verifier"].encode()).digest()
        self.assertEqual(observed["code_challenge"], base64.urlsafe_b64encode(digest).decode().rstrip("="))
        self.assertEqual(form["code"], "synthetic-auth-code")
        with self.assertRaises(GmailError):
            oauth.verify_scope({"scope": oauth.SCOPE + " https://www.googleapis.com/auth/gmail.modify"}, required=True)
