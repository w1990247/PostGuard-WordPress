from datetime import datetime,timedelta,timezone
from typing import Optional
from fastapi import Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt,JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import select
from ..db.session import RetrieveBD
from ..db.models import User,UserRoles
from .settings import settings

pwd_context= CryptContext(schemes=["pbkdf2_sha256"],deprecated="auto")
Oauth2Scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login")

def hashPassword(password: str) ->str:

    return pwd_context.hash(password)


def VerifyPassword(password:str, hashed:str)-> bool:

    return pwd_context.verify(password,hashed)

#The following function  creates a signed token that 
#carries the authenticated users's identity and role.  
def CreateAccessToken(sub:str, role:str)->str:

    now=datetime.now(timezone.utc)
    exp=  now+ timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub":sub,"role":role,"iat":int(now.timestamp()),"exp":int(exp.timestamp())}

    return jwt.encode(payload,settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def GetUserByEmail(db: Session, email: str)-> Optional[User]:
    stmt= select(User).where(User.email ==email)
    return db.execute(stmt).scalar_one_or_none()


def GetCurrentUser(token: str= Depends(Oauth2Scheme), db: Session = Depends(RetrieveBD))-> User:

    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        email= payload.get("sub")

        if not email:
            raise ValueError("Missing Sub")
        
    except (JWTError,ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    user= GetUserByEmail(db,email)

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user

#The following fuction enforces role-based access.
def requireRole(*allowed: UserRoles):

    def Dep(user: User = Depends(GetCurrentUser))-> User:

        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not Allowed!")
        
        return user

    return Dep