import enum
import secrets
import hashlib
from datetime import datetime, timezone
from sqlalchemy import String,DateTime,Integer,Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from api.app.db.session import Base
from sqlalchemy import Enum as SAEnum
from sqlalchemy import Boolean, UniqueConstraint

def UtcNow()-> datetime:
    return datetime.now(timezone.utc)

class RiskScoring(str, enum.Enum):
    allow="allow"
    warn="warn"
    block="block"

class QueueStatus(str, enum.Enum):
    pending= "pending"
    processing="processing"
    done= "done"
    error="error"

class Incident(Base):
    __tablename__= "incidents"

    id: Mapped[int]=mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime]= mapped_column(DateTime(timezone=True), default=UtcNow,nullable=False,)
    window_start: Mapped[datetime]=mapped_column(DateTime(timezone=True), nullable=False,)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,)
    risk_rating: Mapped[RiskScoring]= mapped_column(SAEnum(RiskScoring), default=RiskScoring.allow,nullable=False,)
    risk_reason: Mapped[str]=mapped_column(Text, default="",nullable=False)
    actor_user_id: Mapped[str|None]=mapped_column(String(100), nullable=True)
    directory: Mapped[str|None] = mapped_column(String(1024),nullable=True)
    alert_sent: Mapped[bool] =mapped_column(Boolean, default=False,nullable=False)
    alert_started_at: Mapped[datetime | None] =mapped_column(DateTime(timezone=True), nullable=True)
    alert_sent_at: Mapped[datetime | None] =mapped_column(DateTime(timezone=True), nullable=True)
    alert_last_error: Mapped[str | None] =mapped_column(Text, nullable=True)
    events: Mapped[list["Event"]]= relationship("Event",lazy="selectin")

class Event(Base):
    __tablename__= "events"

    id: Mapped[int]=mapped_column(Integer, primary_key=True, index=True)
    source: Mapped[str]=mapped_column(String(50), nullable=False)
    event_type: Mapped[str]=mapped_column(String(50), nullable=False)
    actor_user_id: Mapped[str|None]=mapped_column(String(100), nullable=True)
    actor_user_name: Mapped[str|None]=mapped_column(String(255), nullable=True)
    path: Mapped[str|None]=mapped_column(String(1024), nullable=True)
    directory: Mapped[str|None]=mapped_column(String(1024), nullable=True)
    meta_json: Mapped[str]=mapped_column(Text, default="{}",nullable=False)
    occurred_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), nullable=False,)
    received_at: Mapped[datetime]= mapped_column(DateTime(timezone=True), default=UtcNow,nullable=False,)
    incident_id:Mapped[int|None]=mapped_column(Integer,ForeignKey("incidents.id"),nullable=True,)

class EventQueueItem(Base):
    __tablename__= "event_queue"
    __table_args__= (UniqueConstraint("event_id",name="uq_event_queue_event_id"),)

    id: Mapped[int]=mapped_column(Integer, primary_key=True, index=True)
    event_id: Mapped[int]=mapped_column(Integer, ForeignKey("events.id"),nullable=False, index=True)
    status: Mapped[QueueStatus]=mapped_column(SAEnum(QueueStatus),default=QueueStatus.pending,nullable=False)
    attempt_count: Mapped[int]=mapped_column(Integer,default=0,nullable=False)
    last_error: Mapped[str|None]=mapped_column(Text,nullable=True)
    created_at: Mapped[datetime]= mapped_column(DateTime(timezone=True), default=UtcNow,nullable=False)
    updated_at: Mapped[datetime]= mapped_column(DateTime(timezone=True), default=UtcNow,nullable=False)
    processed_at: Mapped[datetime|None]= mapped_column(DateTime(timezone=True),nullable=True)



class UserRoles(str, enum.Enum):
    admin="admin"
    analyst="analyst"

class User(Base):
    __tablename__= "users"
    __table_args__= (UniqueConstraint("email",name="uq_user_email"),)

    id: Mapped[int]=mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str]=mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str]=mapped_column(String(255), nullable=False)
    password_hash:Mapped[str]=mapped_column(String(255), nullable=False)
    role: Mapped[UserRoles]= mapped_column(SAEnum(UserRoles), default=UserRoles.analyst,nullable=False,)
    is_active: Mapped[bool]= mapped_column(Boolean,default=True,nullable=False)

class Invite(Base):
    __tablename__= "invites"
    __table_args__= (UniqueConstraint("token_hash",name="uq_invite_token_hash"),)

    id: Mapped[int]=mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str]=mapped_column(String(255), nullable=False, index=True)
    role: Mapped[UserRoles]= mapped_column(SAEnum(UserRoles), nullable=False)
    token_hash: Mapped[str]=mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime]= mapped_column(DateTime(timezone=True), default=UtcNow,nullable=False)


class AlertPolicy(Base):
    __tablename__ ="alert_policies"

    id: Mapped[int]=mapped_column(Integer,primary_key=True,default=1)
    min_risk: Mapped[RiskScoring]=mapped_column(SAEnum(RiskScoring),default=RiskScoring.block,nullable=False)
    send_to_admins:Mapped[bool]=mapped_column(Boolean,default=False,nullable=False)
    send_to_analysts:Mapped[bool]=mapped_column(Boolean,default=False,nullable=False)
    extra_emails_json:Mapped[str]=mapped_column(Text,default="[]",nullable=False)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=UtcNow, onupdate=UtcNow,nullable=False)


class WatcherScope(Base):
    __tablename__ ="watcher_scopes"

    id: Mapped[int]=mapped_column(Integer,primary_key=True,default=1)
    paths_json: Mapped[str]=mapped_column(Text,default="[]",nullable=False)
    ignore_paths_json:Mapped[str]=mapped_column(Text,default="[]",nullable=False)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=UtcNow, onupdate=UtcNow,nullable=False)



def make_invite_token()-> str:
    return secrets.token_urlsafe(32)

def hash_token(token:str)-> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


