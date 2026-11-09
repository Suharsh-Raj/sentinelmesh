from .database import SessionLocal
from .models import Email, Event, LedgerEntry
from .agents.mail_agent import MailAgent

HISTORY = [
 ("billing@amaz0n-support.net","Amazon Billing","Your refund is ready","Verify your account and password to claim your refund today",["https://amazon.com.evil-login.xyz/claim"]),
 ("security@rnicrosoft.com","Microsoft Security","Mailbox storage warning","Sign in immediately to prevent account suspension",["http://rnicrosoft.com/login"]),
 ("updates@google.com","Google Workspace","Monthly security digest","Your monthly account security summary is ready",[]),
 ("notice@paypaI-help.co","PayPal Resolution Center","Action required","Urgent: verify your login credentials within 24 hours",["https://paypai-help.co/secure"]),
 ("hr@university.edu","University HR","Campus benefits enrollment","Enrollment opens Monday. Review the attached guide.",[]),
 ("support@netflix-billing.co","Netflix Support","Payment failed","Update your password and payment details now",["https://netflix-billing.co/update"]),
 ("receipts@apple.com","Apple Store","Order confirmation","Thanks for your recent purchase. Your receipt is attached.",[]),
 ("alerts@amazаn.co","Amazon Support","Order on hold","Sign in now to verify your order details",["https://amazаn.co/account"]),
 ("events@alumni.edu","Alumni Office","Homecoming schedule","We look forward to seeing you at homecoming.",[]),
 ("it@hdfc-secure.co","HDFC Bank","KYC verification","Your account expires today. Verify your OTP immediately.",["https://hdfc-secure.co/kyc"]),
 ("newsletter@sbi.co.in","SBI Updates","Quarterly newsletter","Here are this quarter's service updates.",[]),
 ("help@xn--80ak6aa92e.com","Account Help","Security notice","Confirm your account password to avoid suspension",["https://xn--80ak6aa92e.com"]),
 ("professor@university.edu","Dr. Patel","Seminar notes","Please find the notes from today's seminar.",[]),
 ("team@google.com","Google Drive","Shared project folder","A teammate shared a document with you.",[]),
 ("admin@paypal-verify.click","PayPal Support","Final warning","Your login will expire. Verify credentials now.",["http://paypal-verify.click/login"]),
]

def seed_database():
    with SessionLocal() as db:
        if db.query(Email).count(): return
        agent=MailAgent()
        for sender,name,subject,body,urls in HISTORY:
            result=agent.analyze({"sender":sender,"display_name":name,"subject":subject,"body":body,"urls":urls})
            folder="Quarantine" if result["verdict"] in ("BLOCK","QUARANTINE") else "Inbox"
            email=Email(sender=sender,display_name=name,subject=subject,body=body,urls=urls,verdict=result["verdict"],risk_score=result["risk_score"],reasons=result["reasons"],folder=folder,processed=True)
            db.add(email); db.flush()
            ev=Event(agent="MailAgent",event_type="historical_scan",target=sender,decision=result["verdict"],risk_score=result["risk_score"],reasoning=" ".join(result["reasons"]),evidence=result["reasons"],data={"email_id":email.id,"subject":subject})
            db.add(ev)
            db.add(LedgerEntry(agent="MailAgent",target=sender,decision=result["verdict"],risk_score=result["risk_score"],reasoning=" ".join(result["reasons"]),evidence=result["reasons"],email_id=email.id))
        db.commit()
