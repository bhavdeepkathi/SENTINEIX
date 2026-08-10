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
from app.core.database import AsyncSessionLocal


@pytest.mark.asyncio
async def test_detection_rules():
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

        # --- Test repeated failed logins ---
        async with AsyncSessionLocal() as db:
            now = datetime.utcnow()
            for i in range(5):
                ev = LogEvent(
                    timestamp=now - timedelta(minutes=i),
                    source="test",
                    event_type="login_failed",
                    username="baduser",
                    source_ip="1.2.3.4",
                    hostname="host1",
                    action="Failed password",
                    status="failure",
                    severity="medium",
                    raw_message=f"Failed password for baduser from 1.2.3.4"
                )
                db.add(ev)
            await db.commit()

        # Run detection
        resp = await ac.post("/alerts/run-detection?since_minutes=60", headers=headers)
        assert resp.status_code == 201
        alerts = resp.json()
        assert any(a["title"] == "Repeated Failed Logins" for a in alerts)

        # --- Test suspicious powershell ---
        async with AsyncSessionLocal() as db:
            ev = LogEvent(
                timestamp=datetime.utcnow(),
                source="test",
                event_type="process_creation",
                username="admin",
                source_ip="1.2.3.4",
                hostname="host2",
                action="powershell -enc abc123",
                status="success",
                severity="info",
                raw_message="powershell -enc abc123"
            )
            db.add(ev)
            await db.commit()

        resp = await ac.post("/alerts/run-detection?since_minutes=60", headers=headers)
        assert resp.status_code == 201
        alerts = resp.json()
        assert any(a["title"] == "Suspicious PowerShell Execution" for a in alerts)