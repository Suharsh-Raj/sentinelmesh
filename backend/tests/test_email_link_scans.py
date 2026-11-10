"""Synthetic Gmail and SQLite checks for the offline link queue."""
import asyncio
import unittest
from datetime import timedelta
from threading import Event as ThreadEvent
from time import perf_counter, sleep
from unittest.mock import patch

from sqlalchemy import select, update

from backend import email_link_scans as scans, main as api
from backend.agents.link_agent import analyze_url_static
from backend.models import EmailLinkScan, Event, LedgerEntry, now_utc
from backend.tests import test_gmail as gmail


class AutomaticLinkTests(unittest.TestCase):
    setUp = gmail.GmailTests.setUp
    make_sync = gmail.GmailTests.make_sync
    rows = gmail.GmailTests.rows
    def import_urls(self, message_id, urls):
        item = gmail.message(message_id, ["INBOX"], sender="Fixture <sender@example.org>")
        item["payload"]["body"]["data"] = gmail.text_data("\n".join(urls))
        self.mock.messages[message_id] = item
        self.sync.import_message(self.client, self.config.account_key, gmail.CUTOFF, message_id)
        return self.rows()[message_id].id

    def queue(self):
        with self.sessions() as db:
            return list(db.scalars(select(EmailLinkScan).order_by(EmailLinkScan.position)))

    def test_link_jobs_are_atomic_with_import_and_restarts_are_idempotent(self):
        urls = ["https://example.org/news", "https://google.example.xyz/login", "https://example.org/news"]
        email_id = self.import_urls("fixture", urls)
        self.assertEqual([job.email_id for job in self.queue()], [email_id] * 2)
        # Simulate a process that exited after claiming and before committing.
        claim, _ = scans.claim(self.sessions)
        self.assertIsNone(self.queue()[0].ledger_id)
        with self.sessions.begin() as db:
            db.execute(update(EmailLinkScan).where(EmailLinkScan.id == claim.id)
                       .values(lease_until=now_utc() - timedelta(seconds=1)))
        # Re-open SQLite through an independent engine and poll the same message.
        self.engine.dispose()
        restarted = self.make_sync()
        restarted.import_message(self.client, self.config.account_key, gmail.CUTOFF, "fixture")
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS is forbidden")), \
             patch("socket.socket.connect", side_effect=AssertionError("network is forbidden")):
            self.assertIsNotNone(scans.scan_next(self.sessions, api.chief_agent))
            self.assertIsNotNone(scans.scan_next(self.sessions, api.chief_agent))
        self.assertIsNone(scans.scan_next(self.sessions, api.chief_agent))
        results = self.queue()
        self.assertEqual([job.attempt for job in results], [2, 1])
        self.assertEqual([job.severity for job in results], ["none", "medium"])
        self.assertTrue(all(job.state == "complete" for job in results))
        print("  Static fixtures:", [job.duration_ms for job in results], "ms")
        with patch.object(api, "SessionLocal", self.sessions), patch.object(api, "MAIL_SOURCE", "gmail"):
            ledger = api.get_ledger()
            self.assertEqual(len(ledger), 2)
            self.assertTrue(all(item["email_id"] == email_id for item in ledger))
            self.assertTrue(all(item["link_scan"]["method"] == "static" for item in ledger))
            self.assertTrue(all(item["link_scan"]["browser_state"] == "disabled" for item in ledger))
            self.assertNotIn("https://", str(ledger))
            self.assertEqual(len(api.get_emails()[0]["link_scans"]), 2)
            with self.assertRaises(api.HTTPException):
                asyncio.run(api.revoke(ledger[0]["id"]))
        with self.sessions() as db:
            self.assertEqual(db.query(Event).count(), 2)

    def test_import_rolls_back_if_queue_cannot_be_written(self):
        with patch("backend.gmail_sync.enqueue_email_links", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                self.import_urls("fixture", ["https://example.org/news"])
        self.assertFalse(self.rows())
        self.assertFalse(self.queue())

    def test_limit_skips_and_measured_timeout(self):
        urls = ["https://example.org/unsubscribe?code=synthetic", "https://127.0.0.1:8080/",
                "https://example.org/reset-password", "https://example.org/?signin_token=synthetic"]
        urls.extend(f"https://example.org/article/{n}" for n in range(8))
        self.import_urls("fixture", urls)
        with patch.object(scans, "STATIC_BUDGET_SECONDS", 0.02):
            scans.scan_next(self.sessions, api.chief_agent)
            scans.scan_next(self.sessions, api.chief_agent)
            scans.scan_next(self.sessions, api.chief_agent)
            scans.scan_next(self.sessions, api.chief_agent)

            def slow(url):
                sleep(0.04)
                return analyze_url_static(url)

            scans.scan_next(self.sessions, api.chief_agent, slow)
        while scans.scan_next(self.sessions, api.chief_agent):
            pass
        results = self.queue()
        self.assertEqual([job.state for job in results], ["skipped"] * 4 + ["timed_out"] + ["complete"] * 5 + ["skipped"] * 2)
        self.assertEqual(results[10].evidence, ["Per-message limit reached."])
        self.assertTrue(all(job.severity is None for job in results if job.state != "complete"))
        print(f"  Forced static timeout: {results[4].duration_ms:.3f} ms (20 ms test budget)")

    def test_slow_scan_does_not_block_a_second_import_or_mail_verdict(self):
        self.import_urls("first", ["https://example.org/news"])
        entered, release = ThreadEvent(), ThreadEvent()

        def slow(url):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test failed to release the scan")
            return analyze_url_static(url)

        async def run():
            task = asyncio.create_task(asyncio.to_thread(scans.scan_next, self.sessions, api.chief_agent, slow))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 4))
                started = perf_counter()
                second_id = await asyncio.wait_for(asyncio.to_thread(
                    self.import_urls, "second", ["https://example.org/new"]), 2)
                await asyncio.wait_for(api.process_pending_emails(), 2)
                elapsed = (perf_counter() - started) * 1000
                self.assertEqual(self.rows()["second"].id, second_id)
                self.assertTrue(self.rows()["second"].processed)
                self.assertFalse(task.done())
                with self.sessions() as db:
                    self.assertEqual(db.query(LedgerEntry).filter_by(agent="MailAgent", email_id=second_id).count(), 1)
                print(f"  Second import + MailAgent verdict while scan blocked: {elapsed:.1f} ms")
            finally:
                release.set()
                await task

        with patch.object(api, "SessionLocal", self.sessions):
            asyncio.run(run())
