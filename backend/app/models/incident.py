from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Enum as SQLEnum, Float, func
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


class IncidentStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    closed = "closed"


class IncidentSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    severity = Column(SQLEnum(IncidentSeverity), nullable=False, default=IncidentSeverity.low)
    status = Column(SQLEnum(IncidentStatus), nullable=False, default=IncidentStatus.open)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    owner = relationship("User", foreign_keys=[owner_id])
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    alerts = relationship("Alert", foreign_keys="Alert.incident_id", back_populates="incident")
    mitre_techniques = relationship("MitreTechnique", secondary="incident_mitre", back_populates="incidents")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    log_event_id = Column(Integer, ForeignKey("log_events.id"), nullable=False)
    sequence_no = Column(Integer, nullable=False)

    incident = relationship("Incident", back_populates="events")
    log_event = relationship("LogEvent")