from .database import SessionLocal
from .models import LinkScan, Event, LedgerEntry
from .agents.link_agent import analyze_url

HISTORY=[("https://www.google.com/search?q=campus+calendar","benign"),("https://amazon.com.evil-login.xyz/verify","credential_harvester"),("http://203.0.113.42:8080/update.exe","drive_by_download"),("https://portal.university.edu/resources","benign"),("https://paypaI-security.click/auth/confirm","credential_harvester")]
def seed_links():
    with SessionLocal() as db:
        if db.query(LinkScan).count():return
        for url,scenario in HISTORY:
            r=analyze_url(url,scenario)
            scan=LinkScan(target=url,verdict=r["verdict"],risk_score=r["risk_score"],reasons=r["reasons"],report=r["report"]);db.add(scan);db.flush()
            db.add(Event(agent="LinkAgent",event_type="historical_scan",target=url,decision=r["verdict"],risk_score=r["risk_score"],reasoning=" ".join(r["reasons"]),evidence=r["reasons"],data={"link_id":scan.id}))
            db.add(LedgerEntry(agent="LinkAgent",target=url,decision=r["verdict"],risk_score=r["risk_score"],reasoning=" ".join(r["reasons"]),evidence=r["reasons"]))
        db.commit()
