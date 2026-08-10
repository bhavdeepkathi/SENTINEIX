from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.models.alert import AlertSeverity, AlertStatus


class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.low
    status: AlertStatus = AlertStatus.open
    source_event_id: Optional[int] = None
    incident_id: Optional[int] = None


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    incident_id: Optional[int] = None


class AlertRead(AlertBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True