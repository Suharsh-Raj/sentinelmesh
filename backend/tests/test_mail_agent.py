import unittest
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from backend.agents.mail_agent import MailAgent

agent = MailAgent()

class MailAgentScenarios(unittest.TestCase):
    def test_rnicrosoft_lookalike(self):
        r = agent.analyze({"sender":"security@rnicrosoft.com", "display_name":"Microsoft Security", "subject":"Notice", "body":""})
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertTrue(any("rn-for-m substitution" in x for x in r["reasons"]))

    def test_cyrillic_a_in_amazon(self):
        r = agent.analyze({"sender":"alert@amazаn.com", "display_name":"Amazon", "subject":"Verify now", "body":"Sign in"})
        self.assertEqual(r["verdict"], "BLOCK"); self.assertTrue(any("U+0430" in x and "CYRILLIC" in x for x in r["reasons"]))

    def test_punycode_phish(self):
        r = agent.analyze({"sender":"help@xn--80ak6aa92e.com", "display_name":"Account Help", "subject":"Urgent", "body":""})
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertTrue(any("Punycode domain decodes to 'аррӏе.com'" in x for x in r["reasons"]))
        self.assertTrue(any("impersonates apple.com" in x for x in r["reasons"]))

    def test_legitimate_allowed(self):
        r = agent.analyze({"sender":"news@amazon.com", "display_name":"Amazon", "subject":"Your monthly update", "body":"Here is your receipt"})
        self.assertEqual(r["verdict"], "ALLOW")

    def test_legitimate_sender_cyrillic_name_revoke_allowlist(self):
        r = agent.analyze({"sender":"friend@example.org", "display_name":"Jаne Smith", "subject":"Hello", "body":"See you soon"})
        self.assertEqual(r["verdict"], "QUARANTINE")
        allowed = agent.analyze({"sender":"friend@example.org", "display_name":"Jаne Smith", "subject":"Hello", "body":"See you soon", "allowlisted":True})
        self.assertEqual(allowed["verdict"], "ALLOW")

    def test_all_five_scenarios_have_specific_distinct_reasoning(self):
        scenarios = [
            {"sender":"security@rnicrosoft.com","display_name":"Microsoft Security","subject":"Notice","body":""},
            {"sender":"alert@amazаn.com","display_name":"Amazon Support","subject":"Order verification needed","body":"Sign in now"},
            {"sender":"news@amazon.com","display_name":"Amazon News","subject":"Monthly update","body":"Digest"},
            {"sender":"friend@example.org","display_name":"Jаne Smith","subject":"Coffee tomorrow?","body":"Meet at noon"},
            {"sender":"help@xn--80ak6aa92e.com","display_name":"Account Help","subject":"Security notice","body":"Confirm account password"},
        ]
        results = [agent.analyze(item) for item in scenarios]
        reasoning = [" ".join(result["reasons"]) for result in results]
        self.assertEqual(len(set(reasoning)), 5)
        self.assertEqual([r["verdict"] for r in results], ["BLOCK", "BLOCK", "ALLOW", "QUARANTINE", "BLOCK"])

class MailAgentInboxFlow(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from backend import main as api
        from backend.agents import chief_agent
        from backend.database import Base
        self.api, self.chief = api, chief_agent
        self.original_sessions = api.SessionLocal, chief_agent.SessionLocal
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread":False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        api.SessionLocal = chief_agent.SessionLocal = self.sessions

    async def asyncTearDown(self):
        self.api.SessionLocal, self.chief.SessionLocal = self.original_sessions
        self.engine.dispose()

    async def test_runtime_reports_actual_mail_work_and_lifecycle(self):
        import asyncio
        from unittest.mock import patch

        started, release = asyncio.Event(), asyncio.Event()

        class WaitingModel:
            async def analyze(self, subject, body):
                started.set()
                await release.wait()
                return None

        unavailable = {name: "unavailable" for name in ("MailAgent", "LinkAgent", "ChiefAgent")}
        self.assertEqual(self.api.agent_runtime(), unavailable)
        with patch.multiple(self.api, initialize_database=lambda: None, seed_simulated_data=lambda: None,
                            load_mail_model=WaitingModel, MAIL_SOURCE="simulated"):
            original_model = self.api.mail_model
            try:
                async with self.api.lifespan(self.api.app):
                    expected = {"MailAgent": "active", "LinkAgent": "unavailable", "ChiefAgent": "active"}
                    self.assertEqual(self.api.agent_runtime(), expected)
                    await self.api.submit_email(self.api.EmailInput(sender="fixture@example.org", subject="Fixture"))
                    await asyncio.wait_for(started.wait(), timeout=4)
                    self.assertEqual(self.api.agent_runtime(), {**expected, "MailAgent": "processing"})
                    release.set()
                    for _ in range(50):
                        if self.api.agent_runtime() == expected:
                            break
                        await asyncio.sleep(.01)
                    self.assertEqual(self.api.agent_runtime(), expected)
            finally:
                self.api.mail_model = original_model
        self.assertEqual(self.api.agent_runtime(), unavailable)

    async def test_queued_emails_are_processed_into_decisions_and_revoke(self):
        from backend.models import Email, LedgerEntry, Allowlist
        cases = [
            ("security@rnicrosoft.com", "Microsoft Security", "Notice", "", "BLOCK", "rn-for-m substitution"),
            ("alert@amazаn.com", "Amazon Support", "Order verification needed", "Sign in now", "BLOCK", "U+0430"),
            ("news@amazon.com", "Amazon News", "Monthly update", "Digest", "ALLOW", "No impersonation"),
            ("friend@example.org", "Jаne Smith", "Coffee tomorrow?", "Meet at noon", "QUARANTINE", "U+0430"),
            ("help@xn--80ak6aa92e.com", "Account Help", "Security notice", "Confirm account password", "BLOCK", "аррӏе.com"),
        ]
        final_ids = []
        for sender, name, subject, body, expected, evidence in cases:
            queued = await self.api.submit_email(self.api.EmailInput(sender=sender, display_name=name, subject=subject, body=body))
            self.assertEqual(queued["verdict"], "PENDING")
            self.assertFalse(queued["processed"])
            await self.api.process_pending_emails()
            with self.sessions() as db:
                email = db.get(Email, queued["email_id"])
                self.assertTrue(email.processed)
                self.assertEqual(email.verdict, expected)
                self.assertTrue(any(evidence in reason for reason in email.reasons))
                ledger = db.query(LedgerEntry).filter_by(email_id=email.id).one()
                self.assertEqual(ledger.status, "ACTIVE")
                self.assertIn(evidence, ledger.reasoning)
                final_ids.append(email.id)
        reasonings = []
        with self.sessions() as db:
            reasonings = [db.get(Email, eid).reasons for eid in final_ids]
        self.assertEqual(len({" ".join(r) for r in reasonings}), 5)
        with self.sessions() as db:
            email = db.get(Email, final_ids[3])
            ledger = db.query(LedgerEntry).filter_by(email_id=email.id).one()
            entry_id, sender = ledger.id, email.sender
        revoked = await self.api.revoke(entry_id, who="Evaluator")
        self.assertEqual(revoked["status"], "REVOKED")
        with self.sessions() as db:
            released = db.get(Email, final_ids[3])
            self.assertEqual(released.folder, "Inbox")
            self.assertTrue(db.query(Allowlist).filter_by(sender=sender.lower()).one())
        repeat = await self.api.submit_email(self.api.EmailInput(sender=sender, display_name="Jаne Smith", subject="Another hello", body="Hello"))
        await self.api.process_pending_emails()
        with self.sessions() as db:
            self.assertEqual(db.get(Email, repeat["email_id"]).verdict, "ALLOW")

if __name__ == "__main__": unittest.main()
