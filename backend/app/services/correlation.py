from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from app.models.alert import Alert, AlertStatus
from app.models.incident import Incident, IncidentEvent, IncidentStatus, IncidentSeverity
from app.models.log_event import LogEvent


class CorrelationEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def correlate_alerts(self, since_minutes: int = 60) -> List[Incident]:
        """
        Group open alerts that are related (same user, same host, close time) into incidents.
        Simple heuristic: alerts within 30 minutes, same username or same source_ip.
        """
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        # Get open alerts in window
        stmt = select(Alert).where(
            and_(
                Alert.created_at >= window_start,
                Alert.status == AlertStatus.open,
                Alert.incident_id.is_(None)
            )
        ).order_by(Alert.created_at)
        result = await self.db.execute(stmt)
        alerts = result.scalars().all()

        incidents_created = []
        used = set()

        for alert in alerts:
            if alert.id in used:
                continue
            # Mark seed alert as used before looking for relatives
            used.add(alert.id)
            related = [alert]

            for other in alerts:
                if other.id in used or other.id == alert.id:
                    continue
                if self._are_related(alert, other):
                    related.append(other)
                    used.add(other.id)

            if len(related) >= 1:
                incident = await self._create_incident(related)
                incidents_created.append(incident)
                for a in related:
                    a.incident_id = incident.id
                    a.status = AlertStatus.investigating
                    # already marked used
        await self.db.commit()
        return incidents_created

    def _are_related(self, a1: Alert, a2: Alert) -> bool:
        # Time proximity: within 30 minutes
        time_diff = abs((a1.created_at - a2.created_at).total_seconds())
        if time_diff > 1800:
            return False
        # Same user (if both have source_event with username)
        # We'll need to load source_event usernames; for simplicity, assume alerts have source_event_id
        # This is a simple heuristic; in practice you'd join.
        return True  # For now, consider all within time window related

    async def _create_incident(self, alerts: List[Alert]) -> Incident:
        # Compute risk score
        risk_score = self._calculate_risk_score(alerts)
        severity = self._score_to_severity(risk_score)
        title = f"Correlated Incident: {len(alerts)} alerts"
        description = "Auto-correlated from alerts: " + ", ".join([a.title for a in alerts])

        incident = Incident(
            title=title,
            description=description,
            risk_score=risk_score,
            severity=severity,
            status=IncidentStatus.open,
        )
        self.db.add(incident)
        await self.db.flush()  # get ID

        # Link source events
        for idx, alert in enumerate(alerts):
            if alert.source_event_id:
                ie = IncidentEvent(
                    incident_id=incident.id,
                    log_event_id=alert.source_event_id,
                    sequence_no=idx
                )
                self.db.add(ie)
        return incident

    def _calculate_risk_score(self, alerts: List[Alert]) -> float:
        # Simple scoring: base 10 per alert, severity weights
        severity_weights = {
            "low": 5,
            "medium": 15,
            "high": 30,
            "critical": 50,
        }
        score = 0.0
        for a in alerts:
            score += severity_weights.get(a.severity.value, 5)
        # Cap at 100
        return min(score, 100.0)

    def _score_to_severity(self, score: float) -> IncidentSeverity:
        if score >= 75:
            return IncidentSeverity.critical
        elif score >= 50:
            return IncidentSeverity.high
        elif score >= 25:
            return IncidentSeverity.medium
        else:
            return IncidentSeverity.low