from datetime import timedelta
import json
from sqlalchemy.orm import Session
from sqlalchemy import select,and_,or_
from api.app.core.settings import settings
from api.app.db import models
from datetime import timezone

def UTC(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
#This code groups nearby plugin and theme paths together.
def bucketDirectory(directory:str|None)->str | None:
    if not directory:
        return None
    
    d=directory.replace("\\","/").rstrip("/")
    p= "/wp-content/plugins/"

    if p in d:
        tail= d.split(p,1)[1]
        plugin = tail.split("/",1)[0]
        return d.split(p,1)[0] + p + plugin
    
    t= "/wp-content/themes/"

    if t in d:
        tail= d.split(t,1)[1]
        theme = tail.split("/",1)[0]
        return d.split(t,1)[0] + t + theme
    
    return d



def isFileChange(event_type: str | None)->bool:
    return (event_type or "").lower() in {"create", "modify", "delete", "rename"}


def recentBurstStmt(ev: models.Event):
    event_time =UTC(ev.occurred_at)

    if event_time is None:
        return None
    
    bucket=bucketDirectory(ev.directory)

    if not bucket or not isFileChange(ev.event_type):
        return None
    
    start = event_time - timedelta(seconds=settings.BURST_WINDOW_SECONDS)
    end = event_time + timedelta(seconds=settings.BURST_WINDOW_SECONDS)

    return(
        select(models.Event).where(and_(
            models.Event.occurred_at >= start,
            models.Event.occurred_at <= end,
            models.Event.event_type.in_(["create","modify","delete","rename"]),
        )).order_by(models.Event.occurred_at.asc(),models.Event.id.asc())
    )


#This code treats a short burst of changes as one stronger signal.
def detectBurst(db: Session, ev: models.Event)-> int:
    stmt=recentBurstStmt(ev)

    if stmt is None:
        return 0
    
    seen_ids: set[int] =set()
    
    target_bucket=bucketDirectory(ev.directory)

    for item in db.execute(stmt).scalars().all():

        if bucketDirectory(item.directory) == target_bucket:

            if ev.actor_user_id and item.actor_user_id and item.actor_user_id != ev.actor_user_id:
                continue
            seen_ids.add(item.id)

    
    return len(seen_ids)



def getBurstCountFromMeta(ev:models.Event)-> int:

    try:
        meta=json.loads(ev.meta_json or "{}")
        return int(meta.get("burst_count",0)or 0)
    
    except Exception:
        return 0
    

def eventFamily(ev:models.Event)->str|None:
    source=(ev.source or "").lower()
    event_type=(ev.event_type or "").lower()
    bucket =bucketDirectory(ev.directory)

    if source != "wp_sensor":
        return None
    
    if event_type in {"login","wp_login"}:
        return "auth"
    
    if event_type in {"user_register","user_delete","role_change","profile_update"}:
        return "user_mgmt"
    
    if event_type in {"plugin_activated","plugin_deactivated"}:
        return "plugin_ops"
    
    if event_type == "theme_switched":
        return "theme_ops"
    
    if event_type== "upgrader_completed":

        if bucket and "/wp-content/plugins/" in bucket:
            return "plugin_ops"
        
        if bucket and "/wp-content/themes/" in bucket:
            return "theme_ops"
        
        return "maintenance_ops"
    
    if event_type in {"post_edit","post_delete","upload","add_attachment","delete_attachment"}:
        return "content_ops"

    return "admin_misc"

def incidentPrimaryFamily(db: Session,incident:models.Incident)->str|None:
    primary_event=db.execute(select(models.Event).where(models.Event.incident_id==incident.id)
        .order_by(models.Event.occurred_at.asc(),models.Event.id.asc()).limit(1)).scalars().first()
    
    if primary_event is None:
        return None
    
    return eventFamily(primary_event)
# This code checks if the event matches a existing incident.
def matchesIncident(db:Session,incident: models.Incident, ev:models.Event, bucket: str | None) -> bool:
    same_actor= bool(ev.actor_user_id and incident.actor_user_id and incident.actor_user_id == ev.actor_user_id)

    same_bucket = bool(bucket and incident.directory and incident.directory == bucket)

    if same_actor and same_bucket:
        return True
    
    if isFileChange(ev.event_type):
        
        if same_bucket:
            return True
        
        if same_actor and not bucket:
            return True
        
        return False
    
    if (ev.source or "").lower() =="wp_sensor":
        ev_family=eventFamily(ev)
        incident_family=incidentPrimaryFamily(db,incident)

        if same_actor and ev_family and incident_family and ev_family ==incident_family:
            return True
        
        return False
    
    if same_actor:
        return True
    
    return False

# This code finds the best incident match before creating  a new one.
def findMatchingIncident(db: Session, ev:models.Event)-> models.Incident | None:
    
    TimeWindow = timedelta(seconds=settings.CORRELATION_SECONDS)
    event_time = UTC(ev.occurred_at)
    if event_time is None:
        return None
    Start = event_time -TimeWindow
    End = event_time + TimeWindow
    bucket = bucketDirectory(ev.directory)


    stmt= (select(models.Incident).where(and_(
        models.Incident.window_end >= Start,
        models.Incident.window_start <= End,
        or_(
            models.Incident.actor_user_id == ev.actor_user_id if ev.actor_user_id else False,
            models.Incident.directory == bucket if bucket else False,),
        )
    ).order_by(models.Incident.created_at.desc())

    )

    for incident in db.execute(stmt).scalars().all():

        if matchesIncident(db,incident,ev,bucket):
            return incident
        
    return None
    
    
def recentRelatedEvents(db:Session, ev:models.Event) -> list[models.Event]:

    TimeWindow = timedelta(seconds=settings.CORRELATION_SECONDS)
    event_time = UTC(ev.occurred_at)
    Start = event_time -TimeWindow
    End = event_time + TimeWindow
    bucket = bucketDirectory(ev.directory)

    stmt= (select(models.Event).where(and_(
        models.Event.occurred_at >= Start,
        models.Event.occurred_at <= End,
        )
    ).order_by(models.Event.occurred_at.asc(),models.Event.id.asc())
    
    )

    out=[]

    for item in db.execute(stmt).scalars().all():
        item_bucket = bucketDirectory(item.directory)
        sameActor=bool(ev.actor_user_id and item.actor_user_id and item.actor_user_id==ev.actor_user_id)
        same_bucket = bool(bucket and item_bucket and item_bucket==bucket)

        if isFileChange(ev.event_type):

            if same_bucket and (not ev.actor_user_id or sameActor or not item.actor_user_id):
                out.append(item)

            elif sameActor:
                out.append(item)

        else: 
            if sameActor:
                out.append(item)

    return out



def correlateEvents(db:Session,ev:models.Event)->models.Incident:
    bucket= bucketDirectory(ev.directory)
    burstCount=getBurstCountFromMeta(ev)

    inc = findMatchingIncident(db,ev)

    if inc is None:
        inc =models.Incident(
            window_start=ev.occurred_at,
            window_end=ev.occurred_at,
            actor_user_id=ev.actor_user_id,
            directory=bucket,
        )
        db.add(inc)
        db.flush()
    
    if ev.occurred_at:

        if inc.window_start is None or UTC(ev.occurred_at)<UTC(inc.window_start):
            inc.window_start = ev.occurred_at

        if inc.window_end is None or UTC(ev.occurred_at)> UTC(inc.window_end):
            inc.window_end = ev.occurred_at

    if not inc.actor_user_id and ev.actor_user_id:
        inc.actor_user_id = ev.actor_user_id

    if not inc.directory and bucket:
        inc.directory = bucket
        

    ev.incident_id= inc.id
    db.add(ev)
    db.add(inc)

    if burstCount > settings.BURST_THRESHOLD and bucket and isFileChange(ev.event_type):
        RelatedEvents = recentRelatedEvents(db,ev)

        if RelatedEvents:
            relatedTimes = [UTC(item.occurred_at) for item in RelatedEvents if item.occurred_at]

            if relatedTimes:
                inc.window_start=min(relatedTimes)
                inc.window_end = max(relatedTimes)

            stale_incident_ids: set[int] =set()
            for item in RelatedEvents:

                if item.incident_id and item.incident_id != inc.id:
                    stale_incident_ids.add(item.incident_id)
                item.incident_id = inc.id
                db.add(item)

            for stale_id in stale_incident_ids:
                remaining=db.execute(select(models.Event).where(models.Event.incident_id==stale_id).limit(1)).scalars().first()

                if remaining is None:
                    staleIncident=db.get(models.Incident,stale_id)

                    if staleIncident is not None:
                        db.delete(staleIncident)
    
    return inc

            