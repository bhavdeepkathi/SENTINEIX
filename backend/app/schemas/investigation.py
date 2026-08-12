from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime


class InvestigationBase(BaseModel):
    summary: Optional[str] = None
    attack_type: Optional[str] = None
    attack_sequence: Optional[List[str]] = None
    root_cause: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    confidence: Optional[float] = None
    mitre_techniques: Optional[List[str]] = None


class InvestigationCreate(InvestigationBase):
    pass


class InvestigationRead(InvestigationBase):
    id: int
    incident_id: int
    analyst_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RecommendationCreate(BaseModel):
    investigation_id: Optional[int] = None
    description: str
    priority: Optional[str] = None

class RecommendationUpdate(BaseModel):
    description: Optional[str] = None
    priority: Optional[str] = None

class RecommendationRead(BaseModel):
    id: int
    investigation_id: int
    description: str
    priority: Optional[str] = None
    is_ai_generated: bool

    class Config:
        from_attributes = True