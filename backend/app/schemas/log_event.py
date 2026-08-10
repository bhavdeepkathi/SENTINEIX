from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class LogEventBase(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    raw_message: Optional[str] = None


class LogEventCreate(LogEventBase):
    pass


class LogEventRead(LogEventBase):
    id: int
    incident_id: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True