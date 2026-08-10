from typing import Optional, List
from pydantic import BaseModel

class MitreTechniqueBase(BaseModel):
    technique_id: str
    name: str
    tactic: Optional[str] = None

class MitreTechniqueRead(MitreTechniqueBase):
    class Config:
        from_attributes = True

class IncidentMitreMapping(BaseModel):
    technique_id: str
    name: str
    tactic: Optional[str] = None
    confidence: float
    evidence_ref: Optional[str] = None