"""ChiefAgent event subscriber: decision ledger, revocation history, and incident correlation."""
from datetime import datetime, timezone
from urllib.parse import urlparse
from ..agent_runtime import chief_work
from ..database import SessionLocal
from ..models import Email, LedgerEntry, Incident

class ChiefAgent:
    name = "ChiefAgent"

    @chief_work.track()
    def record_decision(self, db, event):
        stamp = event.get("timestamp")
        if isinstance(stamp, str):
            try:
                stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError:
                stamp = None
        data = event.get("data") or {}
        entry = LedgerEntry(
            timestamp=stamp if isinstance(stamp, datetime) else datetime.now(timezone.utc),
            agent=event["agent"], target=event["target"], decision=event["decision"],
            risk_score=event["risk_score"], reasoning=event["reasoning"], evidence=event["evidence"],
            email_id=data.get("email_id"), ml_analysis=data.get("ml_analysis"),
        )
        db.add(entry)
        return entry

    def handle(self,event):
        if event.get("agent") not in ("MailAgent","LinkAgent"): return
        with chief_work.track(), SessionLocal() as db:
            self.record_decision(db, event)
            if event["agent"]=="LinkAgent" and event["decision"]=="MALICIOUS":
                try: parsed=urlparse(event["target"] if "://" in event["target"] else "https://"+event["target"]); host=(parsed.hostname or "").lower().rstrip(".")
                except ValueError: host=""
                contained = db.query(Email).filter(
                    Email.verdict.in_(["BLOCK", "QUARANTINE"]), Email.revoked.is_(False),
                )
                for mail in contained:
                    domain=mail.sender.rsplit("@",1)[-1].lower().rstrip(".")
                    if not domain or not (host==domain or host.endswith("."+domain)): continue
                    import unicodedata
                    cyrillic=next((f"Cyrillic '{c}'" for c in mail.sender if "CYRILLIC" in unicodedata.name(c,"")),"")
                    brands=("Amazon","Microsoft","Google","PayPal","Apple","Netflix")
                    brand=next((b for b in brands if b.lower() in (mail.display_name+mail.sender).lower()),"a trusted brand")
                    profile=event.get("data",{}).get("report",{})
                    narrative=f"Sender impersonating {brand}"+(f" via {cyrillic}" if cyrillic else "")+" also delivered a link that "+("opened a simulated reverse shell." if profile.get("backdoor") else "showed malicious behavior in the simulated sandbox.")
                    db.add(Incident(severity="CRITICAL",narrative=narrative,evidence=[f"Contained email: {mail.sender}",f"Malicious link: {event['target']}",profile.get("backdoor_detail","")]))
                    break
            db.commit()

    def correlate(self, email_events, link_events):
        incidents = []
        for mail in email_events:
            if mail.get("decision") != "BLOCK": continue
            for link in link_events:
                if link.get("decision") != "MALICIOUS": continue
                if mail.get("target", "").lower().split("@")[-1] in link.get("target", "").lower():
                    incidents.append({"severity": "CRITICAL", "narrative": f"Sender {mail.get('target')} also delivered a malicious link with a potential backdoor."})
        return incidents
