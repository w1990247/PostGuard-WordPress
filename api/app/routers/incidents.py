import csv
import io
import json
from datetime import datetime
from fastapi import Depends,HTTPException, APIRouter, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select, or_, cast, String
from ..db.session import RetrieveBD
from ..db import models
from ..core.auth import requireRole
from ..db.models import UserRoles
from api.app.services.audit_chain import AuditChainWrite
from api.app.services.enrichment import friendlyLocation,fallbackEventLocation

router = APIRouter(prefix="/incidents", tags=["incidents"])
audit= AuditChainWrite()


def parseIso(value: str)-> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def serializeEvent(event: models.Event) -> dict:
    meta = {}
    try:
        meta =json.loads(event.meta_json or "{}")
    except Exception:
        
        meta ={}
        
    where_happened = friendlyLocation(event.path,event.directory)

    if where_happened =="Unknown":
        where_happened =fallbackEventLocation(event.event_type,meta)

    return{
        "id": event.id,
        "source": event.source,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        "received_at": event.received_at.isoformat() if event.received_at else None,
        "path": event.path,
        "directory": event.directory,
        "where_happened": where_happened,
        "actor_user_id": event.actor_user_id,
        "actor_user_name": event.actor_user_name,
        "meta": meta,
    }

def serializeIncident(incident: models.Incident)->dict:
    events= sorted(incident.events or [], key=lambda row: row.occurred_at or row.received_at)
    primary_event= events[-1] if events else None

    reference_time=primary_event.received_at if primary_event and primary_event.received_at else incident.created_at
    alert_latency_seconds = None

    if incident.alert_sent_at and reference_time:
        alert_latency_seconds =round((incident.alert_sent_at-reference_time).total_seconds(),3)

    if primary_event:
        try:
            primary_meta =json.loads(primary_event.meta_json or "{}")
        
        except Exception:
            primary_meta={}

        where_happened =friendlyLocation(primary_event.path,primary_event.directory)

        if where_happened== "Unknown":
            where_happened=fallbackEventLocation(primary_event.event_type,primary_meta)

    else:
        where_happened = friendlyLocation(None,incident.directory)

    actor_user_name =None
    actor_display=""

    if primary_event:
        actor_user_name =primary_event.actor_user_name or None

        if actor_user_name:

            if primary_event.actor_user_id:
                actor_display  =f"{actor_user_name} ({primary_event.actor_user_id})"

            else:
                actor_display=actor_user_name

        elif incident.actor_user_id:
            actor_display=incident.actor_user_id
        
        elif primary_event.source =="watcher":
            actor_display ="watcher/system"
    

    return{
        "id": incident.id,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "window_start": incident.window_start.isoformat() if incident.window_start else None,
        "window_end": incident.window_end.isoformat() if incident.window_end else None,
        "risk_rating": incident.risk_rating.value if incident.risk_rating else None,
        "risk_reason": incident.risk_reason,
        "actor_user_id": incident.actor_user_id,
        "actor_user_name":actor_user_name,
        "actor_display": actor_display,
        "event_count":len(events),
        "directory": incident.directory,
        "where_happened": where_happened,
        "alert_started_at":incident.alert_started_at.isoformat() if incident.alert_started_at else None,
        "alert_sent_at":incident.alert_sent_at.isoformat() if incident.alert_sent_at else None,
        "alert_latency_seconds":alert_latency_seconds,
        "events": [serializeEvent(event) for event in events]

    }



@router.get("")
def ListIncidents(
    risk_rating:str|None=None,
    category: str|None=None,
    date_from: str|None=None,
    date_to: str|None=None,
    q: str|None=None,
    sort: str= Query(default="newest", pattern="^(newest|oldest)$"),
    limit: int=Query(default=100, ge=1,le=500),
    db: Session = Depends(RetrieveBD),
    _: models.User =Depends(requireRole(UserRoles.admin, UserRoles.analyst)),

):
    stmt= select(models.Incident).options(selectinload(models.Incident.events))

    if risk_rating:
        try:
            risk_enum=models.RiskScoring(risk_rating)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid risk rating.")
        
        stmt=stmt.where(models.Incident.risk_rating == risk_enum)

    
    if q:
        like =f"%{q.strip()}%"
        stmt = stmt.where(or_(
            cast(models.Incident.risk_rating, String).ilike(like),
            models.Incident.actor_user_id.ilike(like),
            models.Incident.directory.ilike(like),
        ))

    if category:
        subquery= select(models.Event.incident_id).where(models.Event.event_type == category.strip())
        stmt= stmt.where(models.Incident.id.in_(subquery))

    if date_from:
        try:
            parsed_date_from=parseIso(date_from)
        except ValueError:
            raise HTTPException(status_code=400,detail="Invalid date_from format.")
        
        stmt= stmt.where(models.Incident.window_end>= parsed_date_from)

    if date_to:
        try:
            parsed_date_to = parseIso(date_to)

        except ValueError:
            raise HTTPException(status_code=400,detail="Invalid date_to format.")
        
        stmt= stmt.where(models.Incident.window_start<=parsed_date_to)

    
    orderCol=models.Incident.created_at.asc() if sort== "oldest" else models.Incident.created_at.desc()

    stmt= stmt.order_by(orderCol).limit(limit)

    incidents= db.execute(stmt).scalars().all()

    return[serializeIncident(incident) for incident in incidents]        


@router.get("/export/json")
def exportJson(
    db:Session=Depends(RetrieveBD),
    user: models.User = Depends(requireRole(UserRoles.admin,UserRoles.analyst)),

):
    incidents= db.execute(

        select(models.Incident).options(selectinload(models.Incident.events)).order_by(models.Incident.created_at.desc())).scalars().all()
    

    payload =[serializeIncident(incident) for incident in incidents]
    audit.append({"type":"incidents_export_json","user_id":user.id,"count":len(payload)})

    return Response(

        content= json.dumps(payload, ensure_ascii=False,indent=2),
        media_type="application/json",
        headers={"Content-Disposition":'attachment; filename="postguard-incidents.json"'},
    )


@router.get("/export/csv")
def exportCSV(

    db:Session =Depends(RetrieveBD),
    user:models.User = Depends(requireRole(UserRoles.admin,UserRoles.analyst)),
):
    
    incidents=db.execute(
        select(models.Incident).options(selectinload(models.Incident.events)).order_by(models.Incident.created_at.desc())).scalars().all()

    buffer=io.StringIO()
    writer=csv.writer(buffer)
    writer.writerow([
        "incident_id",
        "risk_rating",
        "risk_reason",
        "window_start",
        "window_end",
        "actor_user_id",
        "directory",
        "event_count",
        "event_id",
        "source",
        "event_type",
        "occurred_at",
        "path",
        "actor_user_name",
    ])
    
    count=0

    for incident in incidents:
        events=incident.events or []
        if not events:
            writer.writerow(
                
                [
                    incident.id,
                    incident.risk_rating.value if incident.risk_rating else "",
                    incident.risk_reason,
                    incident.window_start.isoformat() if incident.window_start else "",
                    incident.window_end.isoformat() if incident.window_end else "",
                    incident.actor_user_id or "",
                    incident.directory or "",
                    0,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )

            count +=1
            continue

        for event in events:
            writer.writerow(
                [
                    incident.id,
                    incident.risk_rating.value if incident.risk_rating else "",
                    incident.risk_reason,
                    incident.window_start.isoformat() if incident.window_start else "",
                    incident.window_end.isoformat() if incident.window_end else "",
                    incident.actor_user_id or "",
                    incident.directory or "",
                    len(events),
                    event.id,
                    event.source,
                    event.event_type,
                    event.occurred_at.isoformat() if event.occurred_at else "",
                    event.path or "",
                    event.actor_user_name or "",
                ]
            )

            count += 1

    audit.append({"type":"incidents_export_csv","user_id": user.id,"count":count})

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="postguard-incidents.csv"'},
    )

@router.get("/{incident_id}")
def getIncident(
    incident_id: int,
    db: Session = Depends(RetrieveBD),
    _: models.User= Depends(requireRole(UserRoles.admin, UserRoles.analyst)),
):
    
    incident=db.execute(
        select(models.Incident).options(selectinload(models.Incident.events)).where(models.Incident.id ==incident_id)
    ).scalars().first()

    if not incident:
        raise HTTPException(status_code=400, detail="Not found")
    
    return serializeIncident(incident)
