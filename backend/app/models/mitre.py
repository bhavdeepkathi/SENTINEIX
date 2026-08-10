from sqlalchemy import Column, Integer, String, Float, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.core.database import Base

# Association table between incidents and MITRE techniques
incident_mitre = Table(
    'incident_mitre',
    Base.metadata,
    Column('incident_id', Integer, ForeignKey('incidents.id'), primary_key=True),
    Column('technique_id', String(20), ForeignKey('mitre_techniques.technique_id'), primary_key=True),
    Column('confidence', Float, nullable=False, default=0.0),
    Column('evidence_ref', String(255), nullable=True)
)

class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id = Column(String(20), primary_key=True)  # e.g., T1059.001
    name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=True)  # e.g., Execution, Persistence

    incidents = relationship("Incident", secondary=incident_mitre, back_populates="mitre_techniques")