from datetime import datetime
from pydantic import BaseModel, Field, model_validator

class EventIn(BaseModel):

    source: str=Field(...,examples=["watcher", "wp_sensor"])
    event_type: str=Field(..., examples=["create","modify","delete","rename"])
    occurred_at: datetime | None =None
    timestamp: datetime | None =None
    actor_user_id: str|None=None
    actor_user_name: str|None=None
    path: str|None=None
    directory: str|None=None
    meta: dict=Field(default_factory=dict)

    @model_validator(mode="after")
    def fillOccurredAt(self):
        
        if self.occurred_at is None and self.timestamp is not None:
            self.occurred_at = self.timestamp

        if self.occurred_at is None:
            raise ValueError("occurred_at or timestamp is required")
        
        return self


class EventOut(BaseModel):
    id: int
    received_at: datetime