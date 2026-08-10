import asyncio
import sys
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import pytest
import uuid
from datetime import datetime, timedelta
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentEvent
from app.models.log_event import LogEvent
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.core.database import AsyncSessionLocal


@pytest.mark.asyncio
async def test_incident_mitre_mapping():
    unique_email = f"test_{uuid.uuid4().hex}@example.com"
    # Setup DB data first
    async with AsyncSessionLocal() as db:
        now = datetime.utcnow()
        inc = Incident(
            title="MITRE Test Incident",
            description="Test mapping",
            risk_score=60.0,
            severity=IncidentSeverity.high,
            status=IncidentStatus.open,
        )
        db.add(inc)
        await db.commit()
        await db.refresh(inc)

        # log event with powershell
        ev1 = LogEvent(
            timestamp=now - timedelta(minutes=5),
            source="test",
            event_type="process_creation",
            username="admin",
            source_ip="1.2.3.4",
            hostname="host1",
            action="powershell -enc abc",
            status="success",
            severity="info",
            raw_message="powershell -enc abc"
        )
        ev2 = LogEvent(
            timestamp=now - timedelta(minutes=3),
            source="test",
            event_type="login_success",
            username="admin",
            source_ip="1.2.3.4",
            hostname="host1",
            action="login",
            status="success",
            severity="info",
            raw_message="login"
        )
        db.add_all([ev1, ev2])
        await db.commit()
        await db.refresh(ev1)
        await db.refresh(ev2)

        # link to incident
        for idx, ev in enumerate([ev1, ev2]):
            ie = IncidentEvent(incident_id=inc.id, log_event_id=ev.id, sequence_no=idx)
            db.add(ie)
        await db.commit()
        inc_id = inc.id

    # Now test endpoint
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/auth/register", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 201
        resp = await ac.post("/auth/login", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = await ac.get(f"/incidents/{inc_id}/mitre", headers=headers)
        assert resp.status_code == 200
        mitre_list = resp.json()
        assert isinstance(mitre_list, list)
        # Expect at least T1059.001 (PowerShell) and T1078 (Valid Accounts)
        tech_ids = {m["technique_id"] for m in mitre_list}
        assert "T1059.001" in tech_ids
        assert "T1078" in tech_ids
        # Check structure
        for m in mitre_list:
            assert "technique_id" in m
            assert "name" in m
            assert "tactic" in m
            assert "confidence" in m
            assert "evidence_ref" in m