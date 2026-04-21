import os
from fastapi import APIRouter,Depends
from sqlalchemy import text,select,func
from sqlalchemy.orm import Session
from api.app.db.session import RetrieveBD
from api.app.core.settings import settings
from api.app.core.redis_client import GET_redis
from api.app.db import models
from api.app.services.event_queue import getWorkerSnapshot

router=APIRouter(tags=["health"])

@router.get("/health")
async def health(db:Session=Depends(RetrieveBD)):
    checks={}
    overall ="ok"

    try:
        db.execute(text("SELECT 1"))
        checks["database"]="ok"
    except Exception as exc:
        checks["database"]= f"fail: {exc}"
        overall  ="fail"

    try: 
        if settings.REDIS:
            redis = GET_redis()
            pong = await redis.ping()
            checks["redis"] = "ok" if pong else "fail"
            if not pong:
                overall= "fail"

        else:
            checks["redis"] = "disabled"
    except Exception as exc:
        checks["redis"] = f"fail: {exc}"

        overall ="fail"

    checks["audit_log_file"] = "ok" if os.path.exists(settings.AUDIT_LOG_PATH) else "missing"
    checks["audit_root_hash"] = "ok" if os.path.exists(settings.AUDIT_ROOT_HASH_PATH) else "missing"
    checks["watcher_scope_file"] = "ok" if os.path.exists(settings.WATCHER_SCOPE_FILE) else "missing"
    checks["ml_model_file"] = "ok" if os.path.exists(settings.ML_MODEL_PATH) else "missing"

    if checks["audit_log_file"]=="missing" or checks["audit_root_hash"]=="missing":
        if overall == "ok":
            overall ="degraded"

    queue_pending = db.execute(
        select(func.count(models.EventQueueItem.id)).where(models.EventQueueItem.status==models.QueueStatus.pending)
    ).scalar_one()

    queue_error = db.execute(
        select(func.count(models.EventQueueItem.id)).where(models.EventQueueItem.status==models.QueueStatus.error)
    ).scalar_one()

    return {
        "status":overall,
        "checks": checks,
        "email_alerts_configured": bool(settings.SMTP_HOST),
        "queue": {
            "pending": int(queue_pending or 0),
            "error": int(queue_error or 0),
        },
        "worker": getWorkerSnapshot(),
        "public_dashboard_url": settings.API_BASE_URL.rstrip("/") + "/",
        "internal_ingest_url": settings.PG_INTERNAL_INGEST_URL,
    }

