from fastapi import APIRouter,Depends
from api.app.db import models
from api.app.core.auth import requireRole
from api.app.services.audit_verify import verifyAuditChain


router= APIRouter(prefix="/audit", tags=["audit"])

@router.get("/verify")
def audit_verify(
    _: models.User =Depends(requireRole(models.UserRoles.admin,models.UserRoles.analyst)),

):
    return verifyAuditChain()