import json
import smtplib
import threading
from email.message import EmailMessage
from sqlalchemy.orm import Session
from api.app.core.settings import settings
from api.app.db import models
from api.app.services.config_store import getOrCreateAlertPolicy
from api.app.services.enrichment import friendlyLocation,fallbackEventLocation
from datetime import datetime,timezone
from api.app.db.session import LocalSession
from api.app.services.audit_chain import AuditChainWrite

RISK_ORDER={
    models.RiskScoring.allow:0,
    models.RiskScoring.warn:1,
    models.RiskScoring.block:2,
}

audit = AuditChainWrite()

def UTCNow() -> datetime:
    return datetime.now(timezone.utc)


def markAlertResult(incident_id: int, success: bool, error:str | None = None)->None:

    db =LocalSession()

    try:
        incident=db.get(models.Incident, incident_id)

        if not incident:
            return
        
        if success:
            incident.alert_sent =True
            incident.alert_sent_at =UTCNow()
            incident.alert_last_error =None

        else: incident.alert_last_error=error

        db.add(incident)
        db.commit()

        audit.append({
            "type": "alert_delivery_result",
            "incident_id": incident_id,
            "success": success,
            "error":error,
        })
    finally:
        db.close()

def riskMeetsThreshhold(risk: models.RiskScoring, threshold: models.RiskScoring) -> bool:
    return RISK_ORDER[risk]>=RISK_ORDER[threshold]

def resolveRecipient(db: Session, policy: models.AlertPolicy) -> list[str]:
    recipients: set[str] = set()

    if policy.send_to_admins:

        for user in db.query(models.User).filter(models.User.role == models.UserRoles.admin,
            models.User.is_active == True,).all():
                recipients.add(user.email.lower())

    if policy.send_to_analysts:

        for user in db.query(models.User).filter(models.User.role == models.UserRoles.analyst,
            models.User.is_active==True,).all():
                recipients.add(user.email.lower())


    try:
            for email in json.loads(policy.extra_emails_json or "[]"):
                if str(email).strip():
                    recipients.add(str(email).lower().strip())

    except Exception:
        pass

    return sorted(recipients)
    
def buildMessage(recipients: list[str], incident: models.Incident) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"[PostGuard] {incident.risk_rating.value.upper()} incident #{incident.id}"
    message["From"] = settings.SMTP_FROM
    message["To"] = ", ".join(recipients)

    dashboard_url= f"{settings.API_BASE_URL.rstrip('/')}/"
    
    events=sorted(incident.events or [],key=lambda row: row.occurred_at or row.received_at)
    primary_event =events[-1] if events else None

    if primary_event:
        try:
            primary_meta=json.loads(primary_event.meta_json or "{}")

        except Exception:
            primary_meta = {}

        where_happened =friendlyLocation(primary_event.path, primary_event.directory)

        if where_happened=="Unknown":
            where_happened = fallbackEventLocation(primary_event.event_type,primary_meta)

    else: 
        where_happened = friendlyLocation(None, incident.directory)

        
    lines = [
        "PostGuard-WordPress generated a live alert.",
        "",
        f"Incident ID: {incident.id}",
        f"Risk rating: {incident.risk_rating.value}",
        f"Reason: {incident.risk_reason or "No reason recorded."}",
        f"Window start: {incident.window_start.isoformat() if incident.window_start else 'n/a'}",
        f"Window end: {incident.window_end.isoformat() if incident.window_end else 'n/a'}",
        f"Actor user ID: {incident.actor_user_id or 'unknown'}",
        f"Where: {where_happened}",
        f"Directory: {incident.directory or 'unknown'}",
        "",
        f"Dashboard: {dashboard_url}",

    ]
    message.set_content("\n".join(lines))
    return message

# The following code sends alerts.
def sendEmailNow(message: EmailMessage,incident_id:int)-> None:
    if not settings.SMTP_HOST:
        markAlertResult(incident_id,False,"SMTP host not configured")
        return
    
    try:
        if settings.SMTP_TLS:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.starttls()

                if settings.SMTP_USER:
                    server.login(settings.SMTP_USER, settings.SMTP_PASS)
                server.send_message(message)

            markAlertResult(incident_id,True,None)
            return
    
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.send_message(message)

        markAlertResult(incident_id,True,None)
    
    except Exception as exc:
         print("Email send failed:", exc)
         markAlertResult(incident_id,False,str(exc))

# The following code makes sure that alerts are sent only if recipients exsist 
# and the threshold is met.
def queueAlertIfNeeded(db:Session, incident: models.Incident) -> bool:
    if incident.alert_sent:
        return False
    
    policy= getOrCreateAlertPolicy(db)
    if not riskMeetsThreshhold(incident.risk_rating, policy.min_risk):
        return False
    
    recipients =resolveRecipient(db, policy)
    if not recipients:
        return False
    
    message= buildMessage(recipients, incident)

    incident.alert_started_at=UTCNow()
    incident.alert_last_error = None

    db.add(incident)
    db.commit()

    thread= threading.Thread(target=sendEmailNow, args=(message,incident.id), daemon=True)

    thread.start()

    return True
         

    
              
     



