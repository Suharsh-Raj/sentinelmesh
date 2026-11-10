import asyncio, json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from .agent_runtime import chief_work, link_work, mail_work
from .database import MAIL_SOURCE, initialize_database, SessionLocal
from .models import Email, EmailLinkScan, Event, LedgerEntry, Allowlist, LinkScan, Incident
from .mail_model import MailModel, load_mail_model
from .gmail_sync import GmailSync
from .email_link_scans import public_scan, scan_worker
from .agents.mail_agent import MailAgent
from .event_bus import bus
from .agents.link_agent import LinkAgent, analyze_file as analyze_uploaded_file
from .agents.chief_agent import ChiefAgent

mail_agent = MailAgent()
mail_model = MailModel("unavailable", error="The local model has not been initialized.")
link_agent = LinkAgent()
chief_agent = ChiefAgent()
bus.add_handler(chief_agent.handle)
gmail_sync = None
runtime_tasks = {}
LOCAL_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

def serialize(obj):
    out = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
    if isinstance(obj, Email):
        out.pop("account_key", None)
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
    """Persist each mail decision and its snapshots before publishing to SSE."""
    with SessionLocal() as db:
        pending = db.query(Email).filter(Email.processed.is_(False)).order_by(Email.id.asc()).limit(50).all()
        pending_ids = [email.id for email in pending]
    for email_id in pending_ids:
        with SessionLocal() as db:
            email = db.get(Email, email_id)
            if email is None or email.processed:
                continue
            subject, body, created_at = email.subject, email.body, email.created_at

        with mail_work.track():
            ml_analysis = await mail_model.analyze(subject, body)
            with SessionLocal.begin() as db:
                email = db.get(Email, email_id)
                if email is None or email.processed or email.created_at != created_at:
                    continue
                allowed = db.query(Allowlist).filter(Allowlist.sender == email.sender.lower()).first() is not None
                result = mail_agent.analyze({"sender":email.sender,"display_name":email.display_name,"subject":email.subject,"body":email.body,"urls":email.urls or [],"reply_to":email.reply_to,"allowlisted":allowed})
                verdict = result["verdict"]
                evidence = result["reasons"]
                # Only the transaction that claims this queued row may add records.
                claimed = db.execute(
                    update(Email)
                    .where(Email.id == email_id, Email.processed.is_(False), Email.created_at == created_at)
                    .values(
                        verdict=verdict, risk_score=result["risk_score"], reasons=evidence,
                        folder="Quarantine" if verdict in ("BLOCK", "QUARANTINE") else "Inbox",
                        processed=True, ml_analysis=ml_analysis,
                    )
                )
                if claimed.rowcount != 1:
                    continue
                event = {
                    "timestamp": datetime.now(timezone.utc),
                    "agent": "MailAgent",
                    "event_type": "email_analyzed",
                    "target": email.sender,
                    "decision": verdict,
                    "risk_score": result["risk_score"],
                    "reasoning": " ".join(evidence),
                    "evidence": evidence,
                    "data": {"email_id": email_id, "subject": subject, "ml_analysis": ml_analysis},
                }
                db.add(Event(**event))
                chief_agent.record_decision(db, event)
            bus.broadcast(event)

async def mail_poller():
    while True:
        try:
            await process_pending_emails()
        except Exception as exc:
            # Keep the inbox watcher alive after an individual database/event error.
            print(f"MailAgent poller error: {type(exc).__name__}")
        await asyncio.sleep(4)

async def gmail_poller(sync, shutdown):
    while not shutdown.is_set():
        delay = await asyncio.to_thread(sync.poll)
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=delay)
        except TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app):
    global mail_model, gmail_sync
    initialize_database()
    mail_model = await asyncio.to_thread(load_mail_model)
    shutdown = asyncio.Event()
    gmail_task = link_task = None
    if MAIL_SOURCE == "simulated":
        seed_simulated_data()
    else:
        gmail_sync = GmailSync(SessionLocal)
        gmail_task = asyncio.create_task(gmail_poller(gmail_sync, shutdown))
        link_task = asyncio.create_task(scan_worker(SessionLocal, chief_agent, bus, shutdown))
    poller = asyncio.create_task(mail_poller())
    runtime_tasks.update(MailAgent=poller, LinkAgent=link_task)
    try:
        yield
    finally:
        runtime_tasks.clear()
        if gmail_task is not None:
            gmail_sync.stop.set()
            shutdown.set()
        poller.cancel()
        try: await poller
        except asyncio.CancelledError: pass
        if gmail_task is not None:
            await asyncio.gather(gmail_task, link_task)
            gmail_sync = None


def seed_simulated_data():
    from .seed import seed_database
    from .seed_links import seed_links
    seed_database()
    seed_links()

app = FastAPI(title="SentinelMesh", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=LOCAL_ORIGINS, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def prevent_private_caching(request, call_next):
    if MAIL_SOURCE == "gmail" and (
        request.headers.get("host", "").split(":", 1)[0].lower() not in ("localhost", "127.0.0.1")
        or request.headers.get("sec-fetch-site") == "cross-site"
        or request.headers.get("origin") not in (None, *LOCAL_ORIGINS)
    ):
        return JSONResponse({"detail": "Use Gmail mode from the local SentinelMesh dashboard."},
                            status_code=403, headers={"Cache-Control": "no-store"})
    response = await call_next(request)
    if MAIL_SOURCE == "gmail":
        response.headers["Cache-Control"] = "no-store"
    return response


def require_simulated():
    if MAIL_SOURCE != "simulated":
        raise HTTPException(403, "Demo injection and reset are unavailable in Gmail mode.")


class EmailInput(BaseModel):
    sender: str = Field(max_length=320)
    display_name: str = Field(default="", max_length=200)
    subject: str = Field(max_length=500)
    body: str = Field(default="", max_length=50000)
    urls: list[str] = Field(default_factory=list, max_length=30)
    reply_to: str = Field(default="", max_length=320)

@app.get("/api/health")
def health(): return {"status": "ok", "service": "SentinelMesh", "agents": ["MailAgent", "LinkAgent", "ChiefAgent"]}

@app.post("/api/emails", dependencies=[Depends(require_simulated)])
async def submit_email(payload: EmailInput):
    require_simulated()
    data = payload.model_dump()
    with SessionLocal() as db:
        email = Email(sender=data["sender"], display_name=data["display_name"], subject=data["subject"], body=data["body"], urls=data["urls"], reply_to=data["reply_to"], verdict="PENDING", risk_score=0, reasons=["Queued for automatic MailAgent inbox processing."], folder="Inbox", processed=False)
        db.add(email); db.commit(); db.refresh(email)
        return {"verdict":"PENDING","risk_score":0,"reasons":email.reasons,"email_id":email.id,"folder":"Inbox","processed":False,"ml_analysis":None}

@app.get("/api/emails")
def get_emails(folder: str | None = None):
    with SessionLocal() as db:
        q = db.query(Email).order_by(Email.created_at.desc())
        if folder: q = q.filter(Email.folder == folder)
        if MAIL_SOURCE != "gmail":
            return [serialize(email) for email in q.all()]
        scans = {}
        job_query = select(EmailLinkScan).order_by(EmailLinkScan.position)
        if folder:
            job_query = job_query.join(Email).where(Email.folder == folder)
        for scan in db.scalars(job_query):
            scans.setdefault(scan.email_id, []).append(public_scan(scan))
        return [dict(serialize(email), link_scans=scans.get(email.id, [])) for email in q.all()]

@app.get("/api/events")
def get_events(limit: int = 100):
    with SessionLocal() as db: return [serialize(x) for x in db.query(Event).order_by(Event.id.desc()).limit(min(limit, 500)).all()]

@app.get("/api/ledger")
def get_ledger():
    with SessionLocal() as db:
        rows = db.execute(select(LedgerEntry, EmailLinkScan).outerjoin(
            EmailLinkScan, EmailLinkScan.ledger_id == LedgerEntry.id,
        ).order_by(LedgerEntry.id.desc()))
        return [dict(serialize(entry), link_scan=public_scan(scan)) if scan else serialize(entry)
                for entry, scan in rows]

def agent_runtime():
    def status(available, activity):
        if not available:
            return "unavailable"
        return "processing" if activity.processing else "active"

    mail = runtime_tasks.get("MailAgent")
    link = runtime_tasks.get("LinkAgent")
    chief_listening = bool(runtime_tasks) and chief_agent.handle in bus.handlers
    return {
        "MailAgent": status(mail is not None and not mail.done(), mail_work),
        "LinkAgent": status(link is not None and not link.done(), link_work),
        "ChiefAgent": status(chief_listening, chief_work),
    }


@app.get("/api/stats")
def get_stats():
    with SessionLocal() as db:
        emails=db.query(Email).all(); entries=db.query(LedgerEntry).all()
        return {"emails_scanned":len(emails),"blocked":sum(e.verdict in ("BLOCK","QUARANTINE") and not e.revoked for e in emails),"links_analyzed":db.query(LinkScan).count(),"incidents":db.query(Incident).count(),"revoked":sum(e.status=="REVOKED" for e in entries),"verdicts":{v:sum(e.verdict==v for e in emails) for v in ("ALLOW","QUARANTINE","BLOCK")},"ml_model":mail_model.describe(),"mail_source":MAIL_SOURCE,"agent_runtime":agent_runtime(),"gmail_sync":gmail_sync.describe() if gmail_sync else None}

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
    event_data = {"ledger_id": entry_id}
    if entry.agent == "MailAgent":
        event_data["ml_analysis"] = entry.ml_analysis
    await emit("ChiefAgent", "decision_revoked", entry.target, "REVOKED", entry.risk_score, f"Operator {who} revoked the decision.", entry.evidence, event_data)
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

@app.post("/api/reset", dependencies=[Depends(require_simulated)])
def reset():
    require_simulated()
    from sqlalchemy import delete
    with SessionLocal() as db:
        for model in (EmailLinkScan, LedgerEntry, Event, Email, Allowlist, LinkScan, Incident): db.execute(delete(model))
        db.commit()
    seed_simulated_data()
    return {"status": "reset"}
