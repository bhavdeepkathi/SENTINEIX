from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Enum as SQLEnum, func
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


class AlertSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    closed = "closed"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(AlertSeverity), nullable=False, default=AlertSeverity.low)
    status = Column(SQLEnum(AlertStatus), nullable=False, default=AlertStatus.open)
    source_event_id = Column(Integer, ForeignKey("log_events.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    source_event = relationship("LogEvent", foreign_keys=[source_event_id])
    incident = relationship("Incident", foreign_keys=[incident_id], back_populates="alerts")