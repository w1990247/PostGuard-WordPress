from pydantic import BaseModel,Field
from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from api.app.db.session import RetrieveBD
from api.app.db import models
from api.app.core.auth import requireRole
from api.app.services.audit_chain import AuditChainWrite
from api.app.services.config_store import(getOrCreateAlertPolicy,policyToDict,updatedAlertPolicy,getOrCreateWatcherScope,
    scopeToDict,updateWatcherScope,)

router= APIRouter(prefix="/config", tags=["config"])

audit=AuditChainWrite()

class AlertPolicyIn(BaseModel):
    min_risk:models.RiskScoring
    send_to_admins:bool=False
    send_to_analysts: bool=False
    extra_emails: list[str]=Field(default_factory=list)


class WatcherScopeIn(BaseModel):
    paths:list[str]
    ignore_paths:list[str]=Field(default_factory=list)

@router.get("/alerts")
def get_alerts(
    db: Session=Depends(RetrieveBD),
    _:models.User=Depends(requireRole(models.UserRoles.admin, models.UserRoles.analyst)),

):
    
    policy= getOrCreateAlertPolicy(db)
    return policyToDict(policy)
#The following code allows admins to change the alert settings.
@router.put("/alerts")
def put_alerts(
    payload: AlertPolicyIn,
    db:Session=Depends(RetrieveBD),
    admin_user: models.User= Depends(requireRole(models.UserRoles.admin)),

):
    policy  =updatedAlertPolicy(
        db,
        min_risk=payload.min_risk,
        send_to_admins=payload.send_to_admins,
        send_to_analysts=payload.send_to_analysts,
        extra_emails=[str(email).lower().strip() for email in payload.extra_emails],
    )

    audit.append({
        "type": "alert_policy_updated", "admin_user_id": admin_user.id, "min_risk": policy.min_risk.value,
        "send_to_admins": policy.send_to_admins, "send_to_analysts": policy.send_to_analysts,
    })
    return policyToDict(policy)

@router.get("/watcher-scope")
def get_watcher_scope(
    db:Session=Depends(RetrieveBD),
    _:models.User=Depends(requireRole(models.UserRoles.admin, models.UserRoles.analyst)),
):
    scope= getOrCreateWatcherScope(db)
    return scopeToDict(scope)
#The following code allows admins to configure the watcher scope.
@router.put("/watcher-scope")
def put_watcher_scope(
    payload: WatcherScopeIn,
    db:Session=Depends(RetrieveBD),
    admin_user: models.User =Depends(requireRole(models.UserRoles.admin)),

):
    
    scope = updateWatcherScope(
        db, paths=[path.strip() for path in payload.paths if path.strip()],
        ignore_paths=[path.strip() for path in payload.ignore_paths if path.strip()],
    )

    current = scopeToDict(scope)
    audit.append({
        "type": "watcher_scope_updated", "admin_user_id": admin_user.id,
        "paths": current["paths"],
        "ignore_paths": current["ignore_paths"],
    })

    return current