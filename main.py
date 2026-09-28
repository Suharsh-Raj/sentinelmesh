import asyncio, json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from .database import Base, engine, SessionLocal
from .models import Email, Event, LedgerEntry, Allowlist, LinkScan, Incident
from .agents.mail_agent import MailAgent
from .event_bus import bus
from .agents.link_agent import LinkAgent, analyze_file as analyze_uploaded_file
from .agents.chief_agent import ChiefAgent

mail_agent = MailAgent()
link_agent = LinkAgent()
chief_agent = ChiefAgent()
bus.add_handler(chief_agent.handle)

def serialize(obj):
    out = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
    for k, v in out.items():
        if isinstance(v, datetime):
            # SQLite drops timezone metadata even for DateTime(timezone=True).
            # All SentinelMesh timestamps are written in UTC, so mark naive
            # values as UTC before the browser parses and renders them locally.
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            else:
                v = v.astimezone(timezone.utc)
            out[k] = v.isoformat()
    return out

async def emit(agent, kind, target, decision, score, reasoning, evidence, data=None):
    event = {"timestamp": datetime.now(timezone.utc), "agent": agent, "event_type": kind,
             "target": target, "decision": decision, "risk_score": score, "reasoning": reasoning,
             "evidence": evidence, "data": data or {}}
    with SessionLocal() as db:
        db.add(Event(**event)); db.commit()
    await bus.publish(event)
    return event

async def process_pending_emails():
    """Score queued inbox rows and publish the decision for ChiefAgent/SSE."""
    with SessionLocal() as db:
        pending = db.query(Email).filter(Email.processed.is_(False)).order_by(Email.id.asc()).limit(50).all()
        pending_ids = [email.id for email in pending]
    for email_id in pending_ids:
        with SessionLocal() as db:
            email = db.get(Email, email_id)
            if email is None or email.processed:
                continue
            allowed = db.query(Allowlist).filter(Allowlist.sender == email.sender.lower()).first() is not None
            result = mail_agent.analyze({"sender":email.sender,"display_name":email.display_name,"subject":email.subject,"body":email.body,"urls":email.urls or [],"reply_to":email.reply_to,"allowlisted":allowed})
            email.verdict = result["verdict"]
            email.risk_score = result["risk_score"]
            email.reasons = result["reasons"]
            email.folder = "Quarantine" if result["verdict"] in ("BLOCK", "QUARANTINE") else "Inbox"
            email.processed = True
            db.commit()
            sender, subject, reasoning, evidence = email.sender, email.subject, " ".join(result["reasons"]), result["reasons"]
        # Commit before publishing: retries cannot create duplicate decisions.
        await emit("MailAgent", "email_analyzed", sender, result["verdict"], result["risk_score"], reasoning, evidence, {"email_id":email_id,"subject":subject})

async def mail_poller():
    while True:
        try:
            await process_pending_emails()
        except Exception as exc:
            # Keep the inbox watcher alive after an individual database/event error.
            print(f"MailAgent poller error: {exc}")
        await asyncio.sleep(4)

@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    # Upgrade databases created before the pending-inbox watcher was added.
    from sqlalchemy import inspect, text
    existing_email_columns = {column["name"] for column in inspect(engine).get_columns("emails")}
    if "processed" not in existing_email_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE emails ADD COLUMN processed BOOLEAN NOT NULL DEFAULT 1"))
    if "reply_to" not in existing_email_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE emails ADD COLUMN reply_to VARCHAR(320) NOT NULL DEFAULT ''"))
    from .seed import seed_database
    seed_database()
    from .seed_links import seed_links
    seed_links()
    poller = asyncio.create_task(mail_poller())
    try:
        yield
    finally:
        poller.cancel()
        try: await poller
        except asyncio.CancelledError: pass

app = FastAPI(title="SentinelMesh", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

class EmailInput(BaseModel):
    sender: str = Field(max_length=320)
    display_name: str = Field(default="", max_length=200)
    subject: str = Field(max_length=500)
    body: str = Field(default="", max_length=50000)
    urls: list[str] = Field(default_factory=list, max_length=30)
    reply_to: str = Field(default="", max_length=320)

@app.get("/api/health")
def health(): return {"status": "ok", "service": "SentinelMesh", "agents": ["MailAgent", "LinkAgent", "ChiefAgent"]}

@app.post("/api/emails")
async def submit_email(payload: EmailInput):
    data = payload.model_dump()
    with SessionLocal() as db:
        email = Email(sender=data["sender"], display_name=data["display_name"], subject=data["subject"], body=data["body"], urls=data["urls"], reply_to=data["reply_to"], verdict="PENDING", risk_score=0, reasons=["Queued for automatic MailAgent inbox processing."], folder="Inbox", processed=False)
        db.add(email); db.commit(); db.refresh(email)
        return {"verdict":"PENDING","risk_score":0,"reasons":email.reasons,"email_id":email.id,"folder":"Inbox","processed":False}

@app.get("/api/emails")
def get_emails(folder: str | None = None):
    with SessionLocal() as db:
        q = db.query(Email).order_by(Email.created_at.desc())
        if folder: q = q.filter(Email.folder == folder)
        return [serialize(x) for x in q.all()]

@app.get("/api/events")
def get_events(limit: int = 100):
    with SessionLocal() as db: return [serialize(x) for x in db.query(Event).order_by(Event.id.desc()).limit(min(limit, 500)).all()]

@app.get("/api/ledger")
def get_ledger():
    with SessionLocal() as db: return [serialize(x) for x in db.query(LedgerEntry).order_by(LedgerEntry.id.desc()).all()]

@app.get("/api/stats")
def get_stats():
    with SessionLocal() as db:
        emails=db.query(Email).all(); entries=db.query(LedgerEntry).all()
        return {"emails_scanned":len(emails),"blocked":sum(e.verdict in ("BLOCK","QUARANTINE") and not e.revoked for e in emails),"links_analyzed":db.query(LinkScan).count(),"incidents":db.query(Incident).count(),"revoked":sum(e.status=="REVOKED" for e in entries),"verdicts":{v:sum(e.verdict==v for e in emails) for v in ("ALLOW","QUARANTINE","BLOCK")}}

class LinkInput(BaseModel):
    url: str = Field(max_length=4096)
    scenario: str = "credential_harvester"

def persist_link(target, scenario, result, scan_type="url"):
    report=result["report"]
    with SessionLocal() as db:
        scan=LinkScan(target=target,scan_type=scan_type,verdict=result["verdict"],risk_score=result["risk_score"],reasons=result["reasons"],report=report)
        db.add(scan);db.flush(); scan_id=scan.id
        event=Event(agent="LinkAgent",event_type="link_analyzed",target=target,decision=result["verdict"],risk_score=result["risk_score"],reasoning=" ".join(result["reasons"]),evidence=result["reasons"],data={"link_id":scan_id,"scenario":scenario})
        db.add(event)
        db.commit()
    return {"id":scan_id,"target":target,"scan_type":scan_type,**result}

@app.post("/api/links/analyze")
async def analyze_link(payload: LinkInput):
    try: result=link_agent.analyze(payload.url,payload.scenario)
    except Exception as e: raise HTTPException(400,f"Unable to analyze URL: {e}")
    out=persist_link(payload.url,payload.scenario,result)
    await bus.publish({"timestamp":datetime.now(timezone.utc).isoformat(),"agent":"LinkAgent","event_type":"link_analyzed","target":payload.url,"decision":result["verdict"],"risk_score":result["risk_score"],"reasoning":" ".join(result["reasons"]),"evidence":result["reasons"],"data":{"link_id":out["id"],"scenario":payload.scenario,"report":result["report"]}})
    return out

@app.post("/api/links/upload")
async def upload_file(file: UploadFile=File(...),scenario: str=Form("drive_by_download")):
    content=await file.read(10*1024*1024+1)
    if len(content)>10*1024*1024: raise HTTPException(413,"File exceeds the 10 MB demo upload limit")
    if not content: raise HTTPException(400,"Uploaded file is empty")
    result=analyze_uploaded_file(file.filename or "upload.bin",content,scenario)
    out=persist_link(file.filename or "upload.bin",scenario,result,"file")
    await bus.publish({"timestamp":datetime.now(timezone.utc).isoformat(),"agent":"LinkAgent","event_type":"file_analyzed","target":out["target"],"decision":result["verdict"],"risk_score":result["risk_score"],"reasoning":" ".join(result["reasons"]),"evidence":result["reasons"],"data":{"link_id":out["id"],"scenario":scenario,"report":result["report"]}})
    return out

@app.get("/api/links")
def get_links():
    with SessionLocal() as db: return [serialize(x) for x in db.query(LinkScan).order_by(LinkScan.id.desc()).all()]

@app.get("/api/incidents")
def get_incidents():
    with SessionLocal() as db: return [serialize(x) for x in db.query(Incident).order_by(Incident.id.desc()).all()]

@app.post("/api/ledger/{entry_id}/revoke")
async def revoke(entry_id: int, who: str = "Operator"):
    with SessionLocal() as db:
        entry = db.get(LedgerEntry, entry_id)
        if entry is None: raise HTTPException(404, "Ledger entry not found")
        revocable = {
            "MailAgent": ("BLOCK", "QUARANTINE"),
            "LinkAgent": ("MALICIOUS", "SUSPICIOUS"),
        }
        if entry.decision not in revocable.get(entry.agent, ()):
            raise HTTPException(400, "This decision cannot be revoked")
        if entry.status == "REVOKED": return serialize(entry)
        entry.status = "REVOKED"; entry.revoked_by = who; entry.revoked_at = datetime.now(timezone.utc)
        email = db.get(Email, entry.email_id) if entry.email_id else None
        if email:
            email.folder = "Inbox"; email.revoked = True
            if not db.query(Allowlist).filter(Allowlist.sender == email.sender.lower()).first(): db.add(Allowlist(sender=email.sender.lower()))
        db.commit(); db.refresh(entry); result = serialize(entry)
    event = await emit("ChiefAgent", "decision_revoked", entry.target, "REVOKED", entry.risk_score, f"Operator {who} revoked the decision.", entry.evidence, {"ledger_id": entry_id})
    return result

@app.get("/api/stream")
async def stream():
    async def events():
        queue = bus.subscribe()
        try:
            while True:
                try: item = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError: yield ": keepalive\n\n"; continue
                yield f"data: {json.dumps(item, default=str)}\n\n"
        finally: bus.unsubscribe(queue)
    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.post("/api/reset")
def reset():
    from sqlalchemy import delete
    with SessionLocal() as db:
        for model in (LedgerEntry, Event, Email, Allowlist, LinkScan, Incident): db.execute(delete(model))
        db.commit()
    from .seed import seed_database
    from .seed_links import seed_links
    seed_database(); seed_links()
    return {"status": "reset"}
