import json
import os
from sqlalchemy.orm import Session
from api.app.core.settings import settings, parse_csv_list
from api.app.db import models

def safeJsonList(raw:str,fallback:list[str] | None=None)-> list[str]:

    try:
        value =json.loads(raw or "[]")

        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        
    except Exception:
        pass

    return list(fallback or [])
# This function stores alert settings in the database.
def getOrCreateAlertPolicy(db: Session)->models.AlertPolicy:
    policy=db.query(models.AlertPolicy).order_by(models.AlertPolicy.id.asc()).first()

    if policy:
        return policy
    
    policy =models.AlertPolicy(
        id=1,
        min_risk=models.RiskScoring.block,
        send_to_admins=False,
        send_to_analysts=False,
        extra_emails_json="[]",
    )

    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy


def policyToDict(policy:models.AlertPolicy)->dict:

    return{
        "min_risk": policy.min_risk.value,
        "send_to_admins": bool(policy.send_to_admins),
        "send_to_analysts": bool(policy.send_to_analysts),
        "extra_emails": safeJsonList(policy.extra_emails_json),
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }

def updatedAlertPolicy(
    db:Session,
    *,
    min_risk: models.RiskScoring,
    send_to_admins: bool,
    send_to_analysts: bool,
    extra_emails: list[str],
)-> models.AlertPolicy:
    policy =getOrCreateAlertPolicy(db)
    policy.min_risk =min_risk
    policy.send_to_admins= bool(send_to_admins)
    policy.send_to_analysts=bool(send_to_analysts)
    policy.extra_emails_json=json.dumps(sorted(set(extra_emails)))
    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy

def getOrCreateWatcherScope(db:Session)->models.WatcherScope:
    scope= db.query(models.WatcherScope).order_by(models.WatcherScope.id.asc()).first()

    if scope:
        return scope
    
    scope=models.WatcherScope(
        id=1,
        paths_json=json.dumps(parse_csv_list(settings.DEFAULT_WATCH_PATHS)),
        ignore_paths_json=json.dumps(parse_csv_list(settings.DEFAULT_WATCH_IGNORE_PATHS)),

    )

    db.add(scope)
    db.commit()
    db.refresh(scope)

    writeScopeFile(scopeToDict(scope))
    return scope

def scopeToDict(scope: models.WatcherScope)->dict:

    return{
        "paths":safeJsonList(scope.paths_json),
        "ignore_paths":safeJsonList(scope.ignore_paths_json),
        "updated_at":scope.updated_at.isoformat() if scope.updated_at else None,

    }
#Save the watcher scope to a file.
def writeScopeFile(scope_dict: dict)->None:
    target =settings.WATCHER_SCOPE_FILE
    os.makedirs(os.path.dirname(target),exist_ok=True)

    with open(target,"w",encoding="utf-8") as i:
        json.dump(scope_dict,i,ensure_ascii=False,indent=2)


def updateWatcherScope(db: Session,*,paths:list[str],ignore_paths:list[str])->models.WatcherScope:
    scope = getOrCreateWatcherScope(db)
    scope.paths_json = json.dumps(sorted(set(paths)))
    scope.ignore_paths_json =json.dumps(sorted(set(ignore_paths)))

    db.add(scope)
    db.commit()
    db.refresh(scope)

    writeScopeFile(scopeToDict(scope))
    return scope