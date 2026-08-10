from sqlalchemy import Column, Integer, String, DateTime, Text, func
from app.core.database import Base


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    event_type = Column(String(100), nullable=False)
    username = Column(String(255), nullable=True)
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    action = Column(String(100), nullable=True)
    status = Column(String(50), nullable=True)
    severity = Column(String(20), nullable=True)
    raw_message = Column(Text, nullable=True)
    incident_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)