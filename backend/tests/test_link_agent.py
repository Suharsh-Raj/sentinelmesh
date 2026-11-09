import hashlib
import io
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.agents.link_agent import EICAR_SIGNATURE, LinkAgent, analyze_file, analyze_url


class LinkStaticAnalysisTests(unittest.TestCase):
    def test_punycode_and_unicode_homoglyph_brand_domain(self):
        result = analyze_url("https://xn--80ak6aa92e.com/login", "benign")
        self.assertIn("Punycode hostname decodes to 'аррӏе.com'.", result["reasons"])
        self.assertTrue(any("homoglyph/lookalike for apple.com" in reason for reason in result["reasons"]))
        self.assertEqual(result["verdict"], "MALICIOUS")

        unicode_result = analyze_url("https://аррӏе.com/login", "benign")
        self.assertTrue(any("U+0430" in reason or "homoglyph/lookalike for apple.com" in reason for reason in unicode_result["reasons"]))

    def test_ip_suspicious_tld_at_sign_and_subdomain_count(self):
        result = analyze_url("http://192.0.2.10@a.b.c.example.click/path", "benign")
        self.assertTrue(any("@ symbol" in reason for reason in result["reasons"]))
        self.assertTrue(any("High-risk top-level domain: .click" in reason for reason in result["reasons"]))
        self.assertTrue(any("3 subdomain labels" in reason for reason in result["reasons"]))
        ip_result = analyze_url("http://[2001:db8::1]:8080/payload", "benign")
        self.assertTrue(any("raw IP host" in reason for reason in ip_result["reasons"]))

    def test_brand_in_subdomain_and_hostname_entropy_and_url_length(self):
        result = analyze_url("https://amazon.com.evil-login.xyz/" + "a" * 120, "benign")
        self.assertTrue(any("Brand name 'amazon' appears in a subdomain" in reason for reason in result["reasons"]))
        self.assertTrue(any("Unusually long URL" in reason for reason in result["reasons"]))
        entropy_result = analyze_url("https://a8zq4m1x9v6k2p7r.example.org/", "benign")
        self.assertTrue(any("high character entropy" in reason for reason in entropy_result["reasons"]))

    def test_file_facts_and_exact_eicar_signature(self):
        content = b"header\n" + EICAR_SIGNATURE + b"\nfooter"
        result = analyze_file("eicar-test.txt", content, "drive_by_download")
        facts = result["report"]["file"]
        self.assertEqual(facts["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(facts["size"], len(content))
        self.assertEqual(facts["type"], "EICAR test signature (plain text)")
        self.assertTrue(facts["eicar"])
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertIn("EICAR test signature found inside uploaded file.", result["reasons"])

    def test_sandbox_profiles_are_prebuilt_and_contain_report_sections(self):
        agent = LinkAgent()
        for scenario in ("credential_harvester", "drive_by_download", "benign", "ransomware_dropper"):
            with self.subTest(scenario=scenario):
                report = agent.analyze("https://www.google.com/", scenario)["report"]
                self.assertEqual(report["scenario"], scenario)
                self.assertEqual(report["profile_badge"], "Simulated behavioral profile")
                self.assertEqual(len(report["timeline"]), 11)
                self.assertTrue(all("cpu" in row and "memory" in row for row in report["timeline"]))
                self.assertTrue(report["process_tree"])
                self.assertTrue(any(":" in item["detail"] for item in report["network"] if item["type"] == "TLS"))
                self.assertTrue(any(item["name"] == "fake-credentials.xlsx" for item in report["honeypot"]["bait"]))
                self.assertIn("files", report)
                self.assertIn("persistence", report)

    def test_expected_demo_url_verdicts(self):
        malicious = analyze_url("https://amazon.com.evil-login.xyz/verify", "credential_harvester")
        benign = analyze_url("https://www.google.com/search?q=campus+calendar", "benign")
        self.assertEqual(malicious["verdict"], "MALICIOUS")
        self.assertEqual(benign["verdict"], "SAFE")


class LinkAgentLedgerFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from backend import main as api
        from backend.agents import chief_agent
        from backend.database import Base

        self.api, self.chief = api, chief_agent
        self.original_sessions = api.SessionLocal, chief_agent.SessionLocal
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        api.SessionLocal = chief_agent.SessionLocal = self.sessions
        self.queue = api.bus.subscribe()

    async def asyncTearDown(self):
        self.api.bus.unsubscribe(self.queue)
        self.api.SessionLocal, self.chief.SessionLocal = self.original_sessions
        self.engine.dispose()

    async def test_url_and_eicar_file_decisions_write_list_evidence_to_chief_ledger_and_sse(self):
        from backend.models import Email, Event, LedgerEntry, LinkScan
        from starlette.datastructures import UploadFile

        url_result = await self.api.analyze_link(self.api.LinkInput(url="https://amazon.com.evil-login.xyz/verify", scenario="credential_harvester"))
        self.assertEqual(url_result["verdict"], "MALICIOUS")
        url_event = await self.queue.get()
        self.assertEqual(url_event["agent"], "LinkAgent")
        self.assertIsInstance(url_event["evidence"], list)

        benign = await self.api.analyze_link(self.api.LinkInput(url="https://www.google.com/search?q=campus+calendar", scenario="benign"))
        self.assertEqual(benign["verdict"], "SAFE")
        benign_event = await self.queue.get()
        self.assertEqual(benign_event["decision"], "SAFE")

        upload = UploadFile(filename="eicar-test.txt", file=io.BytesIO(EICAR_SIGNATURE))
        file_result = await self.api.upload_file(upload, scenario="drive_by_download")
        self.assertEqual(file_result["verdict"], "MALICIOUS")
        self.assertTrue(file_result["report"]["file"]["eicar"])
        self.assertEqual(file_result["report"]["file"]["sha256"], hashlib.sha256(EICAR_SIGNATURE).hexdigest())
        file_event = await self.queue.get()
        self.assertEqual(file_event["agent"], "LinkAgent")
        self.assertIn("EICAR test signature found inside uploaded file.", file_event["evidence"])

        with self.sessions() as db:
            ledger_entries = db.query(LedgerEntry).filter_by(agent="LinkAgent").all()
            self.assertEqual(len(ledger_entries), 3)
            self.assertTrue(all(isinstance(item.evidence, list) and item.evidence for item in ledger_entries))
            self.assertTrue(any(any("EICAR" in signal for signal in item.evidence) for item in ledger_entries))
            self.assertEqual(db.query(LinkScan).count(), 3)
            self.assertEqual(db.query(Event).filter_by(agent="LinkAgent").count(), 3)
            self.assertEqual(db.query(Email).count(), 0)


if __name__ == "__main__":
    unittest.main()
