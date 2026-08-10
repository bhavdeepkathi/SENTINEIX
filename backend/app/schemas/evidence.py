from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class EvidenceBase(BaseModel):
    incident_id: int
    description: Optional[str] = None


class EvidenceCreate(EvidenceBase):
    pass


class EvidenceRead(EvidenceBase):
    id: int
    filename: str
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    sha256: str
    uploaded_by: int
    uploaded_at: datetime

    class Config:
        from_attributes = True


class EvidenceVerify(BaseModel):
    sha256: str
    matches: bool