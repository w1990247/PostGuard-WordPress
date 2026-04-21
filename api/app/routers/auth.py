
from fastapi import Depends,HTTPException, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from api.app.db.session import RetrieveBD
from api.app.core.auth import hashPassword,VerifyPassword,CreateAccessToken,GetCurrentUser
from pydantic import BaseModel
from api.app.db import models
from datetime import datetime,timezone
from api.app.services.audit_chain import AuditChainWrite


router = APIRouter(prefix="/auth", tags=["auth"])
audit =AuditChainWrite()

class RegisterUser(BaseModel):
    display_name: str
    email: str
    password: str
    invite_token:str

class TokenOut(BaseModel):
    access_token: str
    token_type: str= "bearer"

class Out(BaseModel):
    email:str
    role: models.UserRoles
    display_name: str| None =None

class ProfileUpdatedIn(BaseModel):
    display_name: str|None=None
    email: str|None=None
    current_password: str|None=None
    new_password: str|None=None

@router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm= Depends(), db: Session= Depends(RetrieveBD)):
    email= form.username.lower().strip()
    user= db.query(models.User).filter(models.User.email==email).first()

    if not user or not VerifyPassword(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Wrong Credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403,detail="Account is disabled")
    
    token= CreateAccessToken(sub=user.email, role=str(user.role))
    audit.append({"type":"user_login","user_id":user.id, "email":user.email})

    return TokenOut(access_token=token)

@router.get("/out", response_model=Out)
def out(user: models.User=Depends(GetCurrentUser)):
    return Out(email=user.email, role=user.role, display_name=user.display_name)

@router.get("/me", response_model=Out)
def out(user: models.User=Depends(GetCurrentUser)):
    return Out(email=user.email, role=user.role, display_name=user.display_name)
#The following function allows users to update their profile information.
@router.patch("/me", response_model=Out)
def update_me(payload: ProfileUpdatedIn, db:Session= Depends(RetrieveBD),user:models.User=Depends(GetCurrentUser),
    
    ):

    changed=False

    if payload.display_name is not None:
        display_name =payload.display_name.strip()
        if len(display_name)<2:
            raise HTTPException(status_code=400,detail="Display name must be at least two characters.")
        user.display_name=display_name
        changed=True
    
    if payload.email is not None:
        email=str(payload.email).lower().strip()
        existing= db.query(models.User).filter(models.User.email == email,models.User.id !=user.id).first()

        if existing:
            raise HTTPException(status_code=400,detail="Email is already in use.")
        user.email =email
        changed= True
    #Sensitive profile changes can be made afte the current password is entered.
    if payload.new_password:
        if not payload.current_password or not VerifyPassword(payload.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="Current password is not correct.")
        if len(payload.new_password)<8:
            raise HTTPException(status_code=400, detail="New password is too short it must be at least 8 characters.")
        user.password_hash =hashPassword(payload.new_password)
        changed=True

    if not changed:
        raise HTTPException(status_code=400, detail="No changes were made.")
    
    db.add(user)
    db.commit()
    db.refresh(user)

    audit.append(
        {
        "type":"profile_updated", 
        "user_id": user.id, 
        "email": user.email, 
        "changed_email": payload.email is not None,
        "changed_password": bool(payload.new_password), 
        "changed_display_name": payload.display_name is not None,
        }
    )

    return Out (email=user.email,role=user.role,display_name=user.display_name)



#Registration is intive only so accounts get the pre-set role choosen by  
# the admin when creating registration invite.
@router.post("/register", response_model=TokenOut)
def register(payload: RegisterUser, db:Session= Depends(RetrieveBD)):
    display_name= payload.display_name
    email= str(payload.email).lower().strip()
    token_hash= models.hash_token(payload.invite_token)
    inv= db.query(models.Invite).filter(models.Invite.token_hash==token_hash).first()

    if not display_name or len(display_name)<2:
        raise HTTPException(status_code=400, detail="Full Name is required")
    
    if len(payload.password)<8:
        raise HTTPException(status_code=400, detail="New password is too short it must be at least 8 characters.")

    if not inv:
        raise HTTPException(status_code=400, detail="Invalid invite")
    
    now= datetime.now(timezone.utc)


    if inv.email !=email:
        raise HTTPException(status_code=400, detail="Invite and email dont match!")
    
    if inv.used_at is not None:
        raise HTTPException(status_code=400, detail="Invite is already used.")

    expires_at=inv.expires_at

    if expires_at is not None and expires_at.tzinfo is None:
        expires_at= expires_at.replace(tzinfo=timezone.utc)

    if expires_at is not None and expires_at < now:
        raise HTTPException(status_code=400, detail="Invite expired.")

    existing= db.query(models.User).filter(models.User.email== email).first()

    if existing:
        raise HTTPException(status_code=400, detail="User already exists!")
    
    user= models.User(email=email, display_name=display_name, password_hash=hashPassword(payload.password), role=inv.role, is_active=True,)

    db.add(user)
    inv.used_at= now
    db.commit()
    db.refresh(user)

    audit.append({
        "type":"user_registered", "user_id": user.id, "email": user.email, "role": user.role.value,
    })

    token= CreateAccessToken(sub=user.email, role=str(user.role))
    return TokenOut(access_token=token)
