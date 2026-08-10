from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.models.incident import IncidentStatus, IncidentSeverity


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    risk_score: float = 0.0
    severity: IncidentSeverity = IncidentSeverity.low
    status: IncidentStatus = IncidentStatus.open
    owner_id: Optional[int] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    risk_score: Optional[float] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    owner_id: Optional[int] = None


class IncidentRead(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True