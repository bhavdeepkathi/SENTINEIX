from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, LargeBinary, func
from sqlalchemy.orm import relationship
from app.core.database import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_type = Column(String(100), nullable=True)
    file_size = Column(Integer, nullable=True)
    sha256 = Column(String(64), nullable=False, unique=True, index=True)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    description = Column(Text, nullable=True)

    incident = relationship("Incident", foreign_keys=[incident_id])
    uploader = relationship("User", foreign_keys=[uploaded_by])