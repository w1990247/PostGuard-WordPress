from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from api.app.db.session import RetrieveBD
from api.app.db import models
from api.app.core.auth import requireRole
from api.app.services.audit_chain import AuditChainWrite

router= APIRouter(prefix="/users",tags=["users"])
audit =AuditChainWrite()

class UserUpdareIn(BaseModel):

    display_name: str|None=None
    email: str | None=None
    role: models.UserRoles | None=None
    is_active: bool|None=None

def activeAdminCount(db:Session)->int:
    return db.query(models.User).filter(models.User.role == models.UserRoles.admin,
        models.User.is_active == True,).count()


@router.get("")
def listUsers(
    db:Session = Depends(RetrieveBD),_:models.User =Depends(requireRole(models.UserRoles.admin)),
):
    
    rows = db.query(models.User).order_by(models.User.id.asc()).all()
    return [
        {
            "id": user.id,
            "email":user.email,
            "display_name": user.display_name,
            "role": user.role.value,
            "is_active":user.is_active,

        }
        for user in rows
    ]

#The following function allows admins to  manage users.
@router.patch("/{user_id}")
def updateUser(
    user_id: int,
    payload: UserUpdareIn,
    db: Session=Depends(RetrieveBD),
    current_user: models.User = Depends(requireRole(models.UserRoles.admin)),

):
    user=db.get(models.User, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    old_role=user.role
    old_active=user.is_active

    if payload.email is not None:

        email = str(payload.email).lower().strip()
        existing = db.query(models.User).filter(models.User.email ==email,models.User.id != user.id).first()
        
        if existing:
            raise HTTPException(status_code=400, detail="Email is already in use.")
        
        user.email = email

    if payload.display_name is not None:
        dispay_name = payload.display_name.strip()

        if len(dispay_name)<2:
            raise HTTPException(status_code=400, detail="Display name must be at least 2 characters.")
        user.display_name=dispay_name

    if payload.role is not None:
        user.role = payload.role

    if payload.is_active is not None:
        user.is_active = payload.is_active
    #The following code prevents users from locking themselves out.
    if current_user.id== user.id:
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="You cannot disable your own account.")
            
    if current_user.id== user.id and payload.role is not None and payload.role != models.UserRoles.admin:
        raise HTTPException(status_code=400, detail="You cannot remove your own admin role.")
            
    if old_role == models.UserRoles.admin and old_active:
        removing_last_admin=(
            activeAdminCount(db)<= 1 and (user.role != models.UserRoles.admin or user.is_active is False)
        )

        if removing_last_admin:
            raise HTTPException(status_code=400, detail="You cannot remove the last active admin.")
            

    db.add(user)
    db.commit()
    db.refresh(user)

    audit.append(
        {
            "type": "user_updated_by_admin",
            "admin_user_id": current_user.id,
            "target_user_id": user.id,
            "email": user.email,
            "role": user.role.value,
            "is_active": user.is_active,
        }
    )

    return{
        "id":user.id,
        "email":user.email,
        "display_name": user.display_name,
        "role": user.role.value,
        "is_active": user.is_active,
    }

@router.delete("/{user_id}")
def deleteUser(

    user_id: int,
    db: Session = Depends(RetrieveBD),
    current_user: models.User = Depends(requireRole(models.UserRoles.admin)),

):
    user= db.get(models.User, user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    
    if user.role == models.UserRoles.admin and user.is_active and activeAdminCount(db)<=1:
        raise HTTPException(status_code=400, detail="You cannot delete the last active admin.")
    

    audit.append(
        {
            "type":"user_deleted_by_admin",
            "admin_user_id":current_user.id,
            "target_user_id": user.id,
            "email": user.email,
        }
    )

    db.delete(user)
    db.commit()
    return {"status": "delete", "user_id": user_id}

        
