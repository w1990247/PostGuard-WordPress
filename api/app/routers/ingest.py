from fastapi import APIRouter,Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session
from api.app.core.settings import settings
from api.app.core.ingest_security import VerifyTimestamps,VerifySignatures
from api.app.core.redis_client import GET_redis
from api.app.core.rate_limit import RateLimitRedis
from api.app.core.replay import ReplayProtectorRedis
from api.app.db.session import RetrieveBD
from api.app.db import models
from api.app.schemas.events import EventIn, EventOut
from api.app.services.audit_chain import AuditChainWrite
from api.app.services.event_queue import enqueueEvent
import json
import os

router= APIRouter(prefix="/events", tags=["ingest"])
audit = AuditChainWrite()

#The following function normalises events into one schema.
def normalizePayload(payload: EventIn)->dict:
    path = payload.path.replace("\\", "/") if payload.path else None
    directory = payload.directory.replace("\\", "/") if payload.directory else None

    if path and not directory:
        directory = os.path.dirname(path).replace("\\", "/")

    meta = dict(payload.meta or {})

    if payload.source =="wp_sensor" and not path:
        file_path_value = meta.get("filePath") or meta.get("path") or meta.get("file_path")

        if file_path_value:
            path=str(file_path_value).replace("\\", "/")
            if not directory:
                directory = os.path.dirname(path).replace("\\", "/")

    
    return{
        "source": (payload.source or "").strip().lower(),
        "event_type": (payload.event_type or "").strip().lower(),
        "occurred_at": payload.occurred_at,
        "actor_user_id": payload.actor_user_id.strip() if payload.actor_user_id else None,
        "actor_user_name": payload.actor_user_name.strip() if payload.actor_user_name else None,
        "path": path,
        "directory": directory,
        "meta": meta,
    }


@router.post("/ingest", response_model=EventOut)
async def ingest(
    request:Request,
    payload: EventIn,
    pg_api_key: str= Header(..., alias="X-PG-API-KEY"),
    pg_signature: str = Header(..., alias="X-PG-SIGNATURE"),
    pg_timestamp: int= Header(..., alias="X-PG-TIMESTAMP"),
    db: Session= Depends(RetrieveBD),
):
    raw= await request.body()

    redis= GET_redis() if settings.REDIS else None

    try:
        VerifyTimestamps(pg_timestamp)
        VerifySignatures(pg_api_key,pg_timestamp,raw,pg_signature)#
        
        if settings.REDIS:

            limiter=RateLimitRedis(redis,settings.RATE_LIMIT_PER_MINUTE)
            replay = ReplayProtectorRedis(redis, settings.REPLAY_WINDOW_SECONDS)


            await limiter.check(f"{pg_api_key}:{request.url.path}")
            await replay.check_redis(pg_api_key,pg_signature,pg_timestamp,raw)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ingest protection backend unavailable: {e}")

    
    clean =normalizePayload(payload)

    ev= models.Event(
        source=clean["source"],
        event_type=clean["event_type"],
        occurred_at=clean["occurred_at"],
        actor_user_id=clean["actor_user_id"],
        actor_user_name=clean["actor_user_name"],
        path=clean["path"],
        directory=clean["directory"],
        meta_json=json.dumps(clean["meta"],ensure_ascii=False),
    )
    db.add(ev)
    db.flush()
    enqueueEvent(db,ev.id)
    db.commit()
    db.refresh(ev)

    audit.append({
        "type":"event_ingested",
        "event_id":ev.id,
        "source":ev.source,
        "event_type":ev.event_type,
        "occurred_at":ev.occurred_at.isoformat(),
    })
    return EventOut(id=ev.id, received_at=ev.received_at)


    