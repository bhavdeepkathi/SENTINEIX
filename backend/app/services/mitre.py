from typing import List, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.incident import Incident
from app.models.mitre import MitreTechnique, incident_mitre
from app.models.log_event import LogEvent
from app.models.alert import Alert
from app.models.incident import IncidentEvent

class MitreMapper:
    # Simple rule-based mapping from event_type / keywords to MITRE technique IDs
    TECHNIQUE_RULES = {
        "login_failed": [("T1110", "Brute Force")],
        "login_success": [("T1078", "Valid Accounts")],
        "privilege_escalation": [("T1068", "Exploitation for Privilege Escalation")],
        "process_creation": [("T1059.001", "PowerShell")],
        "data_transfer": [("T1041", "Exfiltration Over Command and Control Channel")],
        "malware_indicator": [("T1055", "Process Injection")],
    }

    KEYWORD_RULES = {
        "powershell": ("T1059.001", "PowerShell"),
        "mimikatz": ("T1003.001", "LSASS Memory"),
        "cobaltstrike": ("T1505.003", "Web Shell"),
        "meterpreter": ("T1055", "Process Injection"),
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def map_incident(self, incident: Incident) -> List[Dict]:
        """Return list of mapped techniques with confidence and evidence reference."""
        # Gather related log events via incident_events
        stmt = select(LogEvent).join(IncidentEvent, LogEvent.id == IncidentEvent.log_event_id).where(
            IncidentEvent.incident_id == incident.id
        )
        result = await self.db.execute(stmt)
        log_events = result.scalars().all()

        # Also consider alerts linked to incident
        stmt_alerts = select(Alert).where(Alert.incident_id == incident.id)
        result_alerts = await self.db.execute(stmt_alerts)
        alerts = result_alerts.scalars().all()

        mapped = {}
        # Process log events
        for ev in log_events:
            # rule based on event_type
            for tech_id, tech_name in self.TECHNIQUE_RULES.get(ev.event_type, []):
                self._add_mapping(mapped, tech_id, tech_name, 0.7, f"log_event:{ev.id}")
            # keyword search in raw_message
            if ev.raw_message:
                lowered = ev.raw_message.lower()
                for kw, (tech_id, tech_name) in self.KEYWORD_RULES.items():
                    if kw in lowered:
                        self._add_mapping(mapped, tech_id, tech_name, 0.8, f"log_event:{ev.id}")

        # Process alerts (use title/description)
        for al in alerts:
            text = (al.title or "") + " " + (al.description or "")
            lowered = text.lower()
            for kw, (tech_id, tech_name) in self.KEYWORD_RULES.items():
                if kw in lowered:
                    self._add_mapping(mapped, tech_id, tech_name, 0.6, f"alert:{al.id}")

        # Convert to list of dicts
        results = []
        for tech_id, info in mapped.items():
            results.append({
                "technique_id": tech_id,
                "name": info["name"],
                "tactic": self._tactic_for(tech_id),
                "confidence": info["confidence"],
                "evidence_ref": info["evidence_ref"]
            })
        return results

    def _add_mapping(self, mapped: dict, tech_id: str, name: str, confidence: float, evidence_ref: str):
        if tech_id not in mapped or mapped[tech_id]["confidence"] < confidence:
            mapped[tech_id] = {"name": name, "confidence": confidence, "evidence_ref": evidence_ref}

    def _tactic_for(self, tech_id: str) -> str:
        # Very small static lookup
        tactic_map = {
            "T1110": "Credential Access",
            "T1078": "Initial Access",
            "T1068": "Privilege Escalation",
            "T1059.001": "Execution",
            "T1041": "Exfiltration",
            "T1055": "Defense Evasion",
            "T1003.001": "Credential Access",
            "T1505.003": "Persistence",
        }
        return tactic_map.get(tech_id, "Unknown")