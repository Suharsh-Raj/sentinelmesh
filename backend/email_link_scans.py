"""Offline LinkAgent jobs for newly imported Gmail messages."""
import asyncio
import ipaddress
import re
from datetime import timedelta
from time import perf_counter
from urllib.parse import unquote, urlsplit

from sqlalchemy import or_, select, update

from .agents.link_agent import analyze_url_static
from .models import Email, EmailLinkScan, Event, now_utc

MAX_SCANS_PER_MESSAGE = 10
STATIC_BUDGET_SECONDS = 2
LEASE_SECONDS = 15
ACTION = re.compile(
    r"unsubscribe|opt[-_ ]?out|subscription[-_ /]?preferences|"
    r"magic[-_ /]?link|password[-_ /]?reset|reset[-_ /]?password|"
    r"verify[-_ /]?(?:email|account)|"
    r"confirm[-_ /]?(?:email|account|subscription)|"
    r"(?:^|[?&#])(?:[a-z0-9_-]*token|code|signature|sig|auth|session|"
    r"key|ticket|invite|email|recipient|sso)=", re.I,
)
SPECIAL_HOSTS = {"localhost", "local", "internal", "lan", "home", "corp", "onion"}


def skip_reason(url):
    """Conservative URL-only eligibility check. This never resolves a host."""
    if len(url) > 4096 or re.search(r"[\x00-\x20\x7f\\]", url):
        return "Malformed or oversized URL."
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        parsed.port  # Reject malformed ports, including values out of range.
    except ValueError:
        return "Malformed URL."
    if parsed.scheme not in ("http", "https") or not host:
        return "Only absolute HTTP(S) links are eligible."
    if parsed.username is not None or parsed.password is not None or "%" in host:
        return "URL authority contains credentials or encoding."
    if ACTION.search(unquote(f"{parsed.path}?{parsed.query}#{parsed.fragment}")):
        return "Recognized personalized or account-action link."
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ("." not in host or host.rsplit(".", 1)[-1] in SPECIAL_HOSTS
                or re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*", host)):
            return "Local or non-standard network destination."
    else:
        if not address.is_global or address.is_multicast:
            return "Non-public network destination."
    return None


def enqueue_email_links(db, email_id, urls):
    # MIME already deduplicates exact URL strings and caps its stored list at 30.
    # A position is stable within the immutable imported URL list.
    db.add_all(EmailLinkScan(email_id=email_id, position=position) for position in range(len(urls)))


def claim(sessions):
    now = now_utc()
    ready = select(EmailLinkScan.id).where(or_(
        EmailLinkScan.state == "queued",
        (EmailLinkScan.state == "running") & (EmailLinkScan.lease_until <= now),
    )).order_by(EmailLinkScan.id).limit(1).scalar_subquery()
    with sessions.begin() as db:
        row = db.execute(update(EmailLinkScan).where(EmailLinkScan.id == ready).values(
            state="running", lease_until=now + timedelta(seconds=LEASE_SECONDS),
            attempt=EmailLinkScan.attempt + 1,
        ).returning(EmailLinkScan.id, EmailLinkScan.email_id, EmailLinkScan.position,
                    EmailLinkScan.attempt)).one_or_none()
        if row is None:
            return None
        email = db.get(Email, row.email_id)
        urls = email.urls if email and email.source == "gmail" else []
        url = urls[row.position] if row.position < len(urls) else None
        return row, url


def inspect_link(position, url, inspect=analyze_url_static):
    if position >= MAX_SCANS_PER_MESSAGE:
        return "skipped", None, None, ["Per-message limit reached."], None
    if not isinstance(url, str):
        return "failed", None, None, ["Imported link unavailable."], None
    reason = skip_reason(url)
    if reason:
        return "skipped", None, None, [reason], None

    started = perf_counter()
    try:
        result = inspect(url)
    except Exception:
        # Exception text can contain a private URL.
        return "failed", None, None, ["Static analysis failed."], None
    elapsed = (perf_counter() - started) * 1000
    if elapsed >= STATIC_BUDGET_SECONDS * 1000:
        return "timed_out", None, None, ["Static analysis exceeded its time budget."], round(elapsed, 3)
    return "complete", result["severity"], result["risk_score"], result["reasons"], round(elapsed, 3)


def scan_next(sessions, chief, inspect=analyze_url_static):
    work = claim(sessions)
    if work is None:
        return None
    job, url = work
    state, severity, score, evidence, elapsed = inspect_link(job.position, url, inspect)
    event = {
        "timestamp": now_utc(), "agent": "LinkAgent", "event_type": "email_link_static",
        "target": f"Email #{job.email_id} / link {job.position + 1}",
        "decision": state.upper(), "risk_score": score or 0,
        "reasoning": "Automatic static URL analysis. Browser observation is disabled.",
        "evidence": evidence,
        "data": {"email_id": job.email_id, "link_scan_id": job.id},
    }
    with sessions.begin() as db:
        # Commit evidence, ledger and terminal state together. A worker whose
        # lease was reclaimed cannot publish stale results or duplicate a row.
        result = db.execute(update(EmailLinkScan).where(
            EmailLinkScan.id == job.id, EmailLinkScan.attempt == job.attempt,
            EmailLinkScan.state == "running",
        ).values(state=state, severity=severity, score=score, evidence=evidence,
                 duration_ms=elapsed, lease_until=None))
        if result.rowcount != 1:
            return None
        db.add(Event(**event))
        ledger = chief.record_decision(db, event)
        db.flush()
        db.get(EmailLinkScan, job.id).ledger_id = ledger.id
    return event


def public_scan(scan):
    return {
        "id": scan.id, "position": scan.position + 1, "state": scan.state,
        "severity": scan.severity, "score": scan.score, "evidence": scan.evidence,
        "duration_ms": scan.duration_ms, "method": "static", "browser_state": "disabled",
    }


async def scan_worker(sessions, chief, bus, shutdown):
    while not shutdown.is_set():
        try:
            event = await asyncio.to_thread(scan_next, sessions, chief)
            if event is not None:
                bus.broadcast(event)
                continue
        except Exception as exc:
            print(f"LinkAgent worker error: {type(exc).__name__}")
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=1)
        except TimeoutError:
            pass
