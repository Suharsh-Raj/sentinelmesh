import asyncio
import json
import os
import platform
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import main as api
from backend.database import ensure_schema
from backend.mail_model import DEFAULT_BUNDLE, MailModel, load_mail_model
from backend.models import Allowlist, Email, EmailLinkScan, Event, LedgerEntry


def memory_engine():
    return create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)


def fake_model(scorer=None):
    return MailModel(
        "ready", model_version="fake-test-model", threshold=0.25,
        scorer=scorer or (lambda subject, body: {"phishing_score": 0.0, "model_prediction": "legitimate"}),
    )


class MailModelFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = memory_engine()
        self.addCleanup(self.engine.dispose)
        ensure_schema(self.engine)
        self.sessions = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        for attr, value in (("SessionLocal", self.sessions), ("mail_model", fake_model())):
            replacement = patch.object(api, attr, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.queue = api.bus.subscribe()
        self.addCleanup(api.bus.unsubscribe, self.queue)

    async def submit(self, subject="Synthetic status", body="Weekly agenda"):
        queued = await api.submit_email(api.EmailInput(
            sender="friend@example.org", display_name="Jаne Test", subject=subject, body=body,
        ))
        return queued["email_id"]

    async def test_allowlist_keeps_rule_action_and_persists_zero_ml_score(self):
        with self.sessions.begin() as db:
            db.add(Allowlist(sender="friend@example.org"))
        email_id = await self.submit()
        await api.process_pending_emails()
        email = api.get_emails()[0]
        entry = api.get_ledger()[0]
        event = api.get_events()[0]
        analysis = email["ml_analysis"]
        self.assertEqual(email["id"], email_id)
        self.assertEqual(email["verdict"], "ALLOW")
        self.assertEqual(email["folder"], "Inbox")
        self.assertTrue(any("allowlist" in reason for reason in email["reasons"]))
        self.assertEqual(analysis["status"], "analyzed")
        self.assertEqual(analysis["phishing_score"], 0.0)
        self.assertEqual(analysis["model_prediction"], "legitimate")
        self.assertEqual(analysis["threshold"], 0.25)
        self.assertEqual(analysis["model_version"], "fake-test-model")
        self.assertIsNone(analysis["error"])
        self.assertTrue(analysis["analyzed_at"].endswith("+00:00"))
        self.assertEqual(entry["ml_analysis"], analysis)
        self.assertEqual(entry["evidence"], email["reasons"])
        self.assertEqual(event["data"]["ml_analysis"], analysis)
        self.assertEqual(self.queue.get_nowait()["data"]["ml_analysis"], analysis)
        self.assertEqual(api.get_stats()["ml_model"]["status"], "ready")

    async def test_failed_prediction_is_sanitized_and_later_mail_still_runs(self):
        def score(subject, body):
            if subject == "Synthetic failure":
                raise ValueError(body)
            return {"phishing_score": 0.75, "model_prediction": "phishing"}

        api.mail_model = fake_model(score)
        first = await self.submit("Synthetic failure", "never disclose this input")
        second = await self.submit("Synthetic follow-up")
        await api.process_pending_emails()
        emails = {email["id"]: email for email in api.get_emails()}
        error = emails[first]["ml_analysis"]
        self.assertTrue(emails[first]["processed"])
        self.assertEqual(error["status"], "error")
        self.assertIsNone(error["phishing_score"])
        self.assertNotIn("never disclose", error["error"])
        self.assertEqual(emails[second]["ml_analysis"]["model_prediction"], "phishing")
        self.assertEqual(emails[second]["verdict"], "QUARANTINE")
        self.assertEqual(len(api.get_ledger()), 2)

    async def test_missing_model_still_persists_rule_decision(self):
        with TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"SENTINELMESH_MODEL_DIR": directory, "SENTINELMESH_ML_ENABLED": "1"}):
                api.mail_model = load_mail_model()
        self.assertEqual(api.get_stats()["ml_model"]["status"], "unavailable")
        await self.submit()
        await api.process_pending_emails()
        email = api.get_emails()[0]
        self.assertEqual(email["verdict"], "QUARANTINE")
        self.assertEqual(email["ml_analysis"]["status"], "unavailable")
        self.assertIsNone(email["ml_analysis"]["model_prediction"])
        self.assertIn("SENTINELMESH_MODEL_DIR", email["ml_analysis"]["error"])

    async def test_revoke_preserves_original_ml_and_rule_results(self):
        await self.submit()
        await api.process_pending_emails()
        before = api.get_ledger()[0]
        self.assertEqual(before["decision"], "QUARANTINE")
        self.assertEqual(before["ml_analysis"]["model_prediction"], "legitimate")
        after = await api.revoke(before["id"])
        self.assertEqual(after["status"], "REVOKED")
        for field in ("decision", "risk_score", "reasoning", "evidence", "ml_analysis"):
            self.assertEqual(after[field], before[field])
        released = api.get_emails()[0]
        self.assertEqual(released["folder"], "Inbox")
        self.assertEqual(released["ml_analysis"], before["ml_analysis"])
        self.assertEqual(api.get_events()[0]["data"]["ml_analysis"], before["ml_analysis"])

    async def test_manual_quarantine_round_trip_preserves_gmail_analysis_and_audits_once(self):
        queued = await api.submit_email(api.EmailInput(
            sender="friend@example.org", subject="Synthetic status",
            body="Weekly agenda", urls=["https://example.org"],
        ))
        email_id = queued["email_id"]
        with self.sessions.begin() as db:
            email = db.get(Email, email_id)
            email.source = "gmail"
            email.source_label = "Inbox"
            db.add(EmailLinkScan(email_id=email_id, position=1, state="complete",
                                 severity="none", score=0, evidence=["Synthetic result"]))
        await api.process_pending_emails()
        self.queue.get_nowait()
        original = api.get_ledger()[0]
        move = api.ManualQuarantineInput(quarantined=True, revision=0)
        undo = api.ManualQuarantineInput(quarantined=False, revision=1)
        with patch.object(api, "MAIL_SOURCE", "gmail"):
            before = api.get_emails("Inbox")[0]
            self.assertEqual(before["verdict"], "ALLOW")
            moved = await api.set_manual_quarantine(email_id, move)
            self.assertEqual(moved, await api.set_manual_quarantine(email_id, move))
            self.assertEqual(api.get_emails("Inbox"), [])
            quarantined = api.get_emails("Quarantine")[0]
            self.assertTrue(quarantined["manually_quarantined"])
            restored = await api.set_manual_quarantine(email_id, undo)
            self.assertEqual(restored, await api.set_manual_quarantine(email_id, undo))
            self.assertEqual(api.get_emails("Quarantine"), [])
            after = api.get_emails("Inbox")[0]
            self.assertEqual(quarantined, dict(before, folder="Quarantine", manually_quarantined=True,
                                               manual_quarantine_revision=1))
            self.assertEqual(after, dict(before, manual_quarantine_revision=2))
            with self.assertRaises(HTTPException) as stale:
                await api.set_manual_quarantine(email_id, move)
            self.assertEqual(stale.exception.status_code, 409)
            self.assertEqual(api.get_emails("Inbox")[0], after)
        undone_entry, manual_entry, original_entry = api.get_ledger()
        self.assertEqual(original_entry, original)
        for entry, decision, event_type in (
            (manual_entry, "MANUAL_QUARANTINE", "manual_quarantine"),
            (undone_entry, "MANUAL_QUARANTINE_UNDONE", "manual_quarantine_undone"),
        ):
            self.assertEqual((entry["agent"], entry["decision"], entry["email_id"]),
                             ("Operator", decision, email_id))
            self.assertEqual(self.queue.get_nowait()["data"]["ledger_id"], entry["id"])
            events = [event for event in api.get_events() if event["event_type"] == event_type]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["data"]["ledger_id"], entry["id"])
        self.assertTrue(self.queue.empty())
        with self.sessions() as db:
            self.assertIsNone(db.scalar(select(Allowlist)))

    async def test_manual_undo_does_not_release_automatic_quarantine(self):
        email_id = await self.submit()
        move = api.ManualQuarantineInput(quarantined=True, revision=0)
        with self.assertRaises(HTTPException) as pending:
            await api.set_manual_quarantine(email_id, move)
        self.assertEqual(pending.exception.status_code, 409)
        await api.process_pending_emails()
        self.assertEqual(api.get_emails("Quarantine")[0]["verdict"], "QUARANTINE")
        for request in (move, api.ManualQuarantineInput(quarantined=False, revision=0)):
            with self.assertRaises(HTTPException) as automatic:
                await api.set_manual_quarantine(email_id, request)
            self.assertEqual(automatic.exception.status_code, 409)
        (decision,) = api.get_ledger()
        await api.revoke(decision["id"])
        self.assertTrue(api.get_emails("Inbox")[0]["revoked"])
        with self.sessions() as db:
            self.assertEqual(db.scalar(select(Allowlist)).sender, "friend@example.org")

    async def test_failed_manual_audit_rolls_back_both_folder_transitions(self):
        queued = await api.submit_email(api.EmailInput(sender="friend@example.org", subject="Weekly agenda"))
        await api.process_pending_emails()
        self.queue.get_nowait()
        email_id = queued["email_id"]
        for revision, quarantine in enumerate((True, False)):
            request = api.ManualQuarantineInput(quarantined=quarantine, revision=revision)
            before = (api.get_emails(), api.get_ledger(), api.get_events())
            with patch.object(api.chief_agent, "record_decision", side_effect=RuntimeError("audit failed")):
                with self.assertRaisesRegex(RuntimeError, "audit failed"):
                    await api.set_manual_quarantine(email_id, request)
            self.assertEqual((api.get_emails(), api.get_ledger(), api.get_events()), before)
            self.assertTrue(self.queue.empty())
            await api.set_manual_quarantine(email_id, request)
            self.queue.get_nowait()

    async def test_ledger_write_failure_rolls_back_and_retry_publishes_once(self):
        email_id = await self.submit()
        with patch.object(api.chief_agent, "record_decision", side_effect=RuntimeError("write failure")):
            with self.assertRaises(RuntimeError):
                await api.process_pending_emails()
        email = api.get_emails()[0]
        self.assertFalse(email["processed"])
        self.assertIsNone(email["ml_analysis"])
        self.assertEqual(api.get_events(), [])
        self.assertEqual(api.get_ledger(), [])
        self.assertTrue(self.queue.empty())

        await asyncio.gather(api.process_pending_emails(), api.process_pending_emails())
        await api.process_pending_emails()
        self.assertEqual(len(api.get_ledger()), 1)
        self.assertEqual(len(api.get_events()), 1)
        self.assertEqual(self.queue.get_nowait()["data"]["email_id"], email_id)
        self.assertTrue(self.queue.empty())

    async def test_real_trusted_model_uses_frozen_threshold_and_class_mapping(self):
        bundle_files = (DEFAULT_BUNDLE / "manifest.json", DEFAULT_BUNDLE / "pipeline.joblib")
        if not all(path.is_file() for path in bundle_files):
            self.skipTest("Local Phase 1 bundle is absent.")
        manifest = json.loads(bundle_files[0].read_text(encoding="utf-8"))
        if platform.python_version() != manifest["versions"]["python"]:
            self.skipTest("Run the real bundle smoke test in the matching .ml-venv.")
        with patch.dict(os.environ, {"SENTINELMESH_MODEL_DIR": str(DEFAULT_BUNDLE), "SENTINELMESH_ML_ENABLED": "1"}):
            api.mail_model = load_mail_model()
        self.assertEqual(api.mail_model.status, "ready", api.mail_model.error)
        await self.submit()
        await api.process_pending_emails()
        result = api.get_emails()[0]["ml_analysis"]
        self.assertEqual(result["threshold"], manifest["threshold"])
        self.assertEqual(result["model_version"], manifest["model_version"])
        positive = result["phishing_score"] >= manifest["threshold"]
        self.assertEqual(result["model_prediction"], manifest["class_mapping"][str(int(positive))])
        self.assertEqual(api.get_ledger()[0]["ml_analysis"], result)

        from ml.artifact import predict
        import numpy as np

        pipeline = SimpleNamespace(predict_proba=lambda texts: np.array(
            [[1 - manifest["threshold"], manifest["threshold"]]]
        ))
        self.assertEqual(predict(pipeline, manifest, "Synthetic boundary")["model_prediction"], "phishing")


class MailModelStartupTests(unittest.TestCase):
    def test_disabled_model_does_not_load_bundle(self):
        with patch.dict(os.environ, {"SENTINELMESH_ML_ENABLED": "0"}):
            self.assertEqual(load_mail_model().status, "disabled")

    def test_incompatible_model_is_explicit_without_echoing_exception(self):
        def reject(directory):
            raise ValueError("Incompatible model dependencies: internal diagnostics")

        artifact_module = SimpleNamespace(load_bundle=reject, predict=None)
        with TemporaryDirectory() as directory:
            for name in ("manifest.json", "pipeline.joblib"):
                (Path(directory) / name).touch()
            with patch.dict(os.environ, {"SENTINELMESH_MODEL_DIR": directory, "SENTINELMESH_ML_ENABLED": "1"}):
                with patch.dict(sys.modules, {"ml.artifact": artifact_module}):
                    model = load_mail_model()
        self.assertEqual(model.status, "error")
        self.assertIn("dependency versions", model.error)
        self.assertNotIn("internal diagnostics", model.error)


class MailMigrationTests(unittest.TestCase):
    def test_legacy_rows_survive_repeated_additive_migration(self):
        engine = memory_engine()
        self.addCleanup(engine.dispose)
        ensure_schema(engine)
        sessions = sessionmaker(bind=engine)
        with sessions.begin() as db:
            email = Email(sender="history@example.org", subject="Historical row", verdict="ALLOW",
                          risk_score=0, reasons=["Original evidence"])
            db.add(email)
            db.flush()
            db.add(LedgerEntry(agent="MailAgent", target=email.sender, decision=email.verdict,
                               evidence=email.reasons, email_id=email.id))
        with engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE emails DROP COLUMN ml_analysis")
            connection.exec_driver_sql("ALTER TABLE emails DROP COLUMN manually_quarantined")
            connection.exec_driver_sql("ALTER TABLE emails DROP COLUMN manual_quarantine_revision")
            connection.exec_driver_sql("ALTER TABLE ledger DROP COLUMN ml_analysis")
        ensure_schema(engine)
        ensure_schema(engine)
        with sessions() as db:
            email = db.scalars(select(Email)).one()
            entry = db.scalars(select(LedgerEntry)).one()
            self.assertTrue(email.processed)
            self.assertFalse(email.manually_quarantined)
            self.assertEqual(email.manual_quarantine_revision, 0)
            self.assertEqual(email.reasons, ["Original evidence"])
            self.assertEqual(entry.evidence, email.reasons)
            self.assertIsNone(email.ml_analysis)
            self.assertIsNone(entry.ml_analysis)
        with patch.object(api, "SessionLocal", sessions):
            asyncio.run(api.process_pending_emails())
        with sessions() as db:
            self.assertIsNone(db.scalars(select(Email)).one().ml_analysis)
            self.assertEqual(len(db.scalars(select(LedgerEntry)).all()), 1)
            self.assertEqual(db.scalars(select(Event)).all(), [])
