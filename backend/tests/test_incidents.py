import asyncio
import sys
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import pytest
import uuid
from datetime import datetime, timedelta
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.log_event import LogEvent
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentEvent
from app.core.database import AsyncSessionLocal


@pytest.mark.asyncio
async def test_correlate_alerts():
    unique_email = f"test_{uuid.uuid4().hex}@example.com"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # register and login
        resp = await ac.post("/auth/register", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 201
        resp = await ac.post("/auth/login", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Insert log events and alerts directly
        async with AsyncSessionLocal() as db:
            now = datetime.utcnow()
            # create two log events
            ev1 = LogEvent(
                timestamp=now - timedelta(minutes=5),
                source="test",
                event_type="login_failed",
                username="baduser",
                source_ip="1.2.3.4",
                hostname="host1",
                action="Failed password",
                status="failure",
                severity="medium",
                raw_message="Failed password for baduser from 1.2.3.4"
            )
            ev2 = LogEvent(
                timestamp=now - timedelta(minutes=3),
                source="test",
                event_type="login_failed",
                username="baduser",
                source_ip="1.2.3.4",
                hostname="host1",
                action="Failed password",
                status="failure",
                severity="medium",
                raw_message="Failed password for baduser from 1.2.3.4"
            )
            db.add_all([ev1, ev2])
            await db.commit()
            await db.refresh(ev1)
            await db.refresh(ev2)

            # create alerts linked to those events
            al1 = Alert(
                title="Repeated Failed Logins",
                description="User baduser from 1.2.3.4 had 5 failed login attempts",
                severity=AlertSeverity.medium,
                status=AlertStatus.open,
                source_event_id=ev1.id,
            )
            al2 = Alert(
                title="Repeated Failed Logins",
                description="User baduser from 1.2.3.4 had 5 failed login attempts",
                severity=AlertSeverity.medium,
                status=AlertStatus.open,
                source_event_id=ev2.id,
            )
            db.add_all([al1, al2])
            await db.commit()

        # Run correlation
        resp = await ac.post("/incidents/correlate?since_minutes=60", headers=headers)
        assert resp.status_code == 201
        incidents = resp.json()
        assert isinstance(incidents, list)
        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc["title"].startswith("Correlated Incident")
        assert inc["risk_score"] > 0
        assert "severity" in inc
        # Check timeline endpoint
        inc_id = inc["id"]
        resp = await ac.get(f"/incidents/{inc_id}/timeline", headers=headers)
        assert resp.status_code == 200
        tl = resp.json()
        assert tl["incident_id"] == inc_id
        assert isinstance(tl["timeline"], list)
        assert len(tl["timeline"]) >= 1


@pytest.mark.asyncio
async def test_timeline_filters():
    unique_email = f"test_{uuid.uuid4().hex}@example.com"
    # First, set up DB data before creating the test client to avoid loop mismatch
    async with AsyncSessionLocal() as db:
        now = datetime.utcnow()
        # create incident
        inc = Incident(
            title="Filter Test Incident",
            description="Testing timeline filters",
            risk_score=30.0,
            severity=IncidentSeverity.medium,
            status=IncidentStatus.open,
        )
        db.add(inc)
        await db.commit()
        await db.refresh(inc)

        # create multiple log events with different attributes
        ev1 = LogEvent(
            timestamp=now - timedelta(minutes=10),
            source="src1",
            event_type="login_failed",
            username="alice",
            source_ip="10.0.0.1",
            hostname="hostA",
            action="fail",
            status="failure",
            severity="high",
            raw_message="msg1"
        )
        ev2 = LogEvent(
            timestamp=now - timedelta(minutes=5),
            source="src2",
            event_type="login_success",
            username="bob",
            source_ip="10.0.0.2",
            hostname="hostB",
            action="success",
            status="success",
            severity="low",
            raw_message="msg2"
        )
        ev3 = LogEvent(
            timestamp=now - timedelta(minutes=1),
            source="src1",
            event_type="login_failed",
            username="alice",
            source_ip="10.0.0.1",
            hostname="hostA",
            action="fail",
            status="failure",
            severity="high",
            raw_message="msg3"
        )
        db.add_all([ev1, ev2, ev3])
        await db.commit()
        await db.refresh(ev1)
        await db.refresh(ev2)
        await db.refresh(ev3)

        # link to incident
        for idx, ev in enumerate([ev1, ev2, ev3]):
            ie = IncidentEvent(incident_id=inc.id, log_event_id=ev.id, sequence_no=idx)
            db.add(ie)
        await db.commit()
        inc_id = inc.id

    # Now create client and authenticate
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/auth/register", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 201
        resp = await ac.post("/auth/login", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Test filter by username=alice
        resp = await ac.get(f"/incidents/{inc_id}/timeline?username=alice", headers=headers)
        assert resp.status_code == 200
        tl = resp.json()
        assert all(item["username"] == "alice" for item in tl["timeline"])
        assert len(tl["timeline"]) == 2

        # Filter by event_type=login_success
        resp = await ac.get(f"/incidents/{inc_id}/timeline?event_type=login_success", headers=headers)
        assert resp.status_code == 200
        tl = resp.json()
        assert all(item["event_type"] == "login_success" for item in tl["timeline"])
        assert len(tl["timeline"]) == 1

        # Filter by severity=high
        resp = await ac.get(f"/incidents/{inc_id}/timeline?severity=high", headers=headers)
        assert resp.status_code == 200
        tl = resp.json()
        assert all(item["severity"] == "high" for item in tl["timeline"])
        assert len(tl["timeline"]) == 2

        # Time range filter
        start = (now - timedelta(minutes=7)).isoformat()
        end = (now - timedelta(minutes=3)).isoformat()
        resp = await ac.get(f"/incidents/{inc_id}/timeline?start_time={start}&end_time={end}", headers=headers)
        assert resp.status_code == 200
        tl = resp.json()
        # should include ev2 (5 min ago) only
        assert len(tl["timeline"]) == 1

        # Pagination
        resp = await ac.get(f"/incidents/{inc_id}/timeline?skip=1&limit=1", headers=headers)
        assert resp.status_code == 200
        tl = resp.json()
        assert len(tl["timeline"]) == 1