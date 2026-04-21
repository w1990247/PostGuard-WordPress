import asyncio
import json
from datetime import datetime,timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from api.app.core.settings import settings
from api.app.db import models
from api.app.db.session import LocalSession
from api.app.services.audit_chain import AuditChainWrite
from api.app.services.alerts import queueAlertIfNeeded
from api.app.services.correlation import correlateEvents,detectBurst
from api.app.services.enrichment import enrichEventContext
from api.app.services.risk_scoring import score_events



audit = AuditChainWrite()

worker_task: asyncio.Task | None=None
stop_event: asyncio.Event |None = None
last_beat: datetime | None = None

def UTCNow()-> datetime:
    return datetime.now(timezone.utc)

def riskStrength(value: models.RiskScoring) ->int:

    order={
        models.RiskScoring.allow:0,
        models.RiskScoring.warn:1,
        models.RiskScoring.block:2,
    }

    return order[value]

def enqueueEvent(db: Session, event_id:int) -> None:
    row = models.EventQueueItem(event_id=event_id, status=models.QueueStatus.pending)
    db.add(row)

#This code recovers stuck items left after restart.
def recoverStuckQueueItems(db: Session) -> int:
    rows = db.execute(select(models.EventQueueItem).where(models.EventQueueItem.status == models.QueueStatus.processing)
    ).scalars().all()

    recovered =0
    for row in rows:
        row.status = models.QueueStatus.pending
        row.updated_at = UTCNow()
        db.add(row)
        recovered +=1

    if recovered:
        db.commit()
        audit.append({
            "type":"queue_recovered_after_restart",
            "recovered_count": recovered,
        })

    return recovered


def getWorkerSnapshot()->dict:

    return{
        "running": bool(worker_task and not worker_task.done()),
        "last_beat": last_beat.isoformat() if last_beat else None,

    }
# The following function process one stored event through the pipeline.
def processQueueRow(db: Session, row: models.EventQueueItem) -> None:

    row.status = models.QueueStatus.processing
    row.attempt_count +=1
    row.updated_at =UTCNow()
    db.add(row)
    db.commit()

    event=db.get(models.Event, row.event_id)

    if not event:
        row.status = models.QueueStatus.error
        row.last_error= "Event not found."
        row.updated_at=UTCNow()
        db.add(row)
        db.commit()
        return
    

    meta={}
    try:
        meta=json.loads(event.meta_json or "{}")

    except Exception:
        meta= {}

    meta = enrichEventContext(event.path,event.directory,event.source,meta)
    burst_count= detectBurst(db,event)
    meta["burst_count"] = burst_count
    event.meta_json =json.dumps(meta, ensure_ascii=False)

    risk_rating, risk_reason = score_events(event.event_type, event.path, event.source, meta, event.actor_user_id,)

    incident = correlateEvents(db, event)

    if riskStrength(risk_rating) > riskStrength(incident.risk_rating):
        incident.risk_rating= risk_rating
        incident.risk_reason = risk_reason

    elif not incident.risk_reason:
        incident.risk_reason = risk_reason

    row.status = models.QueueStatus.done
    row.processed_at = UTCNow()
    row.updated_at =UTCNow()

    db.add(event)
    db.add(incident)
    db.add(row)
    db.commit()
    db.refresh(incident)

    alertStarted= queueAlertIfNeeded(db, incident)

    audit.append(
        {
            "type": "event_scored_and_correlated",
            "event_id": event.id,
            "incident_id": incident.id,
            "risk": incident.risk_rating.value,
            "reason": incident.risk_reason,
            "burst_count": burst_count,
            "alert_started": alertStarted,
        }
    )

def claimBatch(db: Session, batch_size: int)-> list[models.EventQueueItem]:
    stmt =(select(models.EventQueueItem).where(models.EventQueueItem.status==models.QueueStatus.pending)
        .order_by(models.EventQueueItem.created_at.asc()).limit(batch_size)
    )

    return db.execute(stmt).scalars().all()

#This function process queued events in the background.
async def workerLoop(stop_event: asyncio.Event) -> None:
    global last_beat

    while not stop_event.is_set():
        last_beat =UTCNow()

        db=LocalSession()
        try:
            rows = claimBatch(db, settings.SCORER_BATCH_SIZE)

            for row in rows:

                try:
                    processQueueRow(db,row)
                except Exception as exc:

                    row.status = models.QueueStatus.error
                    row.last_error =str(exc)
                    row.updated_at= UTCNow()
                    db.add(row)
                    db.commit()

                    audit.append(
                        {
                            "type": "queue_processing_error",
                            "queue_id":row.id,
                            "event_id":row.event_id,
                            "error": str(exc),
                        }
                    )
        finally:
            db.close()
        await asyncio.sleep(settings.SCORER_POLL_SECONDS)


async def startWorker() -> None:
    global worker_task,stop_event

    if worker_task and not worker_task.done():
        return
    
    stop_event=asyncio.Event()
    worker_task = asyncio.create_task(workerLoop(stop_event))


async def stopWorker() -> None:
    global worker_task, stop_event

    if not worker_task:
        return
    
    if stop_event:
        stop_event.set()

    try:
        await asyncio.wait_for(worker_task,timeout=5)

    except Exception:
        worker_task.cancel()

    worker_task = None
    stop_event = None
