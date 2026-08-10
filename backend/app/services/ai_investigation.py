import json
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.incident import Incident
from app.models.log_event import LogEvent
from app.models.alert import Alert
from app.models.evidence import Evidence
from app.models.mitre import MitreTechnique
from app.models.investigation import Investigation, Recommendation
from app.services.llm_client import llm_client


class AIInvestigationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def run_investigation(self, incident: Incident, analyst_id: int) -> Investigation:
        # Gather context
        context = await self._build_context(incident)
        # Build prompt
        prompt = self._build_prompt(context)
        # Call LLM
        try:
            raw = await llm_client.chat_completion([
                {"role": "system", "content": "You are a senior cybersecurity analyst. Output only valid JSON."},
                {"role": "user", "content": prompt}
            ])
        except Exception as e:
            # If LLM call fails (e.g., missing API key), fall back to mock data
            mock_data = {
                "incident_summary": f"Automated mock investigation for incident {incident.id}",
                "attack_type": "Mock",
                "attack_sequence": ["Mock step 1", "Mock step 2"],
                "root_cause": "LLM unavailable, using mock data",
                "affected_assets": ["asset1", "asset2"],
                "confidence": 0.5,
                "mitre_techniques": ["T1000"],
                "recommendations": [
                    {"description": "Enable LLM integration", "priority": "high"},
                    {"description": "Review logs manually", "priority": "medium"}
                ]
            }
            raw = json.dumps(mock_data)

        # Parse JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # fallback: wrap raw
            data = {
                "incident_summary": "Failed to parse AI output",
                "attack_type": "Unknown",
                "attack_sequence": [],
                "root_cause": "AI output parsing error",
                "affected_assets": [],
                "confidence": 0,
                "mitre_techniques": [],
                "recommendations": []
            }

        # Persist investigation
        investigation = Investigation(
            incident_id=incident.id,
            analyst_id=analyst_id,
            summary=data.get("incident_summary"),
            attack_type=data.get("attack_type"),
            attack_sequence=json.dumps(data.get("attack_sequence", [])),
            root_cause=data.get("root_cause"),
            affected_assets=json.dumps(data.get("affected_assets", [])),
            confidence=data.get("confidence", 0),
            mitre_techniques=json.dumps(data.get("mitre_techniques", [])),
        )
        self.db.add(investigation)
        await self.db.flush()

        # Persist recommendations
        for rec in data.get("recommendations", []):
            rec_obj = Recommendation(
                investigation_id=investigation.id,
                description=rec.get("description", ""),
                priority=rec.get("priority", "medium"),
                is_ai_generated=1,
            )
            self.db.add(rec_obj)

        await self.db.commit()
        await self.db.refresh(investigation)
        return investigation

    async def _build_context(self, incident: Incident) -> Dict[str, Any]:
        # Log events via incident_events
        from app.models.incident import IncidentEvent
        stmt = select(LogEvent).join(IncidentEvent, LogEvent.id == IncidentEvent.log_event_id).where(
            IncidentEvent.incident_id == incident.id
        ).order_by(IncidentEvent.sequence_no)
        result = await self.db.execute(stmt)
        log_events = result.scalars().all()

        # Alerts
        stmt_a = select(Alert).where(Alert.incident_id == incident.id)
        result_a = await self.db.execute(stmt_a)
        alerts = result_a.scalars().all()

        # Evidence
        stmt_e = select(Evidence).where(Evidence.incident_id == incident.id)
        result_e = await self.db.execute(stmt_e)
        evidence = result_e.scalars().all()

        # MITRE techniques
        stmt_m = select(MitreTechnique).join(
            __import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre,
            MitreTechnique.technique_id == __import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre.c.technique_id
        ).where(__import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre.c.incident_id == incident.id)
        # Simpler: use association table
        from app.models.mitre import incident_mitre
        stmt_m = select(MitreTechnique).join(incident_mitre, MitreTechnique.technique_id == incident_mitre.c.technique_id).where(
            incident_mitre.c.incident_id == incident.id
        )
        result_m = await self.db.execute(stmt_m)
        mitre_techniques = result_m.scalars().all()

        return {
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "risk_score": incident.risk_score,
                "severity": incident.severity.value if incident.severity else None,
                "status": incident.status.value if incident.status else None,
            },
            "log_events": [
                {
                    "timestamp": ev.timestamp.isoformat(),
                    "source": ev.source,
                    "event_type": ev.event_type,
                    "username": ev.username,
                    "source_ip": ev.source_ip,
                    "hostname": ev.hostname,
                    "action": ev.action,
                    "status": ev.status,
                    "severity": ev.severity,
                } for ev in log_events
            ],
            "alerts": [
                {
                    "title": a.title,
                    "description": a.description,
                    "severity": a.severity.value if a.severity else None,
                } for a in alerts
            ],
            "evidence": [
                {
                    "filename": e.filename,
                    "file_type": e.file_type,
                    "sha256": e.sha256,
                } for e in evidence
            ],
            "mitre_techniques": [
                {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic} for t in mitre_techniques
            ]
        }

    def _build_prompt(self, context: Dict[str, Any]) -> str:
        return f"""
You are given structured incident data. Produce a JSON object with the following keys:
- incident_summary (string)
- attack_type (string)
- attack_sequence (array of strings, chronological)
- root_cause (string)
- affected_assets (array of strings)
- confidence (number 0-1)
- mitre_techniques (array of technique IDs observed)
- recommendations (array of objects with description, priority)

Incident data:
{json.dumps(context, indent=2)}

Return ONLY the JSON object.
""".strip()