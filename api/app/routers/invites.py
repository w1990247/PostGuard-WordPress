from datetime import datetime,timedelta, timezone
from pydantic import BaseModel
from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from api.app.db.session import RetrieveBD
from api.app.db import models
from api.app.core.auth import requireRole
from api.app.services.audit_chain import AuditChainWrite
import smtplib
import threading
from email.message import EmailMessage
from api.app.core.settings import settings


router =APIRouter(prefix="/invites", tags=["intives"])
audit = AuditChainWrite()

def sendInviteEmailNow(recipient:str,subject:str,body:str)->None:
    
    if not settings.SMTP_HOST:
        return
    
    message=EmailMessage()
    message["Subject"]=subject
    message["From"] =settings.SMTP_FROM
    message["To"] =recipient
    message.set_content(body)

    try:
        if settings.SMTP_TLS:

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.starttls()

                if settings.SMTP_USER:
                    server.login(settings.SMTP_USER, settings.SMTP_PASS)
                server.send_message(message)
        
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT,timeout=15) as server:

                if settings.SMTP_USER:
                    server.login(settings.SMTP_USER, settings.SMTP_PASS)
                server.send_message(message)

    except Exception as exc:
        print("Invite email send failed:",exc)


def queueInviteEmail(recipient:str,role:models.UserRoles, token:str, expires_at:datetime)->None:
    register_url =f"{settings.API_BASE_URL.rstrip('/')}/register.html?token={token}"

    subject ="[PostGuard] Your invite to PostGuard-Wordpress"

    body= "\n".join([
        "You have been invited to PostGuard-WordPress",
        "",
        f"Email: {recipient}",
        f"Role: {role.value}",
        f"Invite token: {token}",
        f"Expires at: {expires_at.isoformat()}",
        "",
        f"Register here: {register_url}",
    ])
    
    thread = threading.Thread(target=sendInviteEmailNow,args=(recipient,subject,body),daemon=True)
    thread.start()



class InviteCreate(BaseModel):
    email: str
    role: models.UserRoles
    expires_minutes: int=60 *24

class InviteCreateOut(BaseModel):
    email: str
    role: models.UserRoles
    invite_token: str
    expires_at: datetime
    register_url: str

@router.post("", response_model=InviteCreateOut)
def createInvite(

    payload: InviteCreate,
    db: Session=Depends(RetrieveBD),
    AdminS: models.User= Depends(requireRole(models.UserRoles.admin)),

):
    token= models.make_invite_token()
    token_hash= models.hash_token(token)
    expires_at= datetime.now(timezone.utc)+ timedelta(minutes=payload.expires_minutes)
    inv= models.Invite(email=str(payload.email).lower(), role=payload.role, token_hash=token_hash, expires_at=expires_at, used_at=None,)
    db.add(inv)
    db.commit()
    db.refresh(inv)

    audit.append(
        {
            "type":"invite_created",
            "admin_user_id": AdminS.id,
            "email":inv.email,
            "role":inv.role.value,
            "expires_at": inv.expires_at.isoformat(),

        }
    )
    
    reg_url=f"/register.html?token={token}"

    queueInviteEmail(recipient=inv.email,role=inv.role,token=token,expires_at=inv.expires_at,)
    
    return InviteCreateOut(email=inv.email,role=inv.role,invite_token=token,expires_at=inv.expires_at,register_url=reg_url,)

