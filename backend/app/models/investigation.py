from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, func
from sqlalchemy.orm import relationship
from app.core.database import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, unique=True)
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    summary = Column(Text, nullable=True)
    attack_type = Column(String(255), nullable=True)
    attack_sequence = Column(Text, nullable=True)  # JSON string list
    root_cause = Column(Text, nullable=True)
    affected_assets = Column(Text, nullable=True)  # JSON string list
    confidence = Column(Float, nullable=True)
    mitre_techniques = Column(Text, nullable=True)  # JSON string list
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    incident = relationship("Incident", foreign_keys=[incident_id])
    analyst = relationship("User", foreign_keys=[analyst_id])
    recommendations = relationship("Recommendation", back_populates="investigation", cascade="all, delete-orphan")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=False)
    description = Column(Text, nullable=False)
    priority = Column(String(20), nullable=True)  # high, medium, low
    is_ai_generated = Column(Integer, default=1)  # boolean as int

    investigation = relationship("Investigation", back_populates="recommendations")