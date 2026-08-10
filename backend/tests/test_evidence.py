import asyncio
import sys
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.core.database import AsyncSessionLocal


@pytest.mark.asyncio
async def test_evidence_upload_and_verify():
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

        # Create an incident first
        async with AsyncSessionLocal() as db:
            inc = Incident(
                title="Test Incident",
                description="For evidence test",
                risk_score=50.0,
                severity=IncidentSeverity.high,
                status=IncidentStatus.open,
            )
            db.add(inc)
            await db.commit()
            await db.refresh(inc)
            incident_id = inc.id

        # Upload a simple text file
        file_content = b"This is test evidence content."
        files = {"file": ("test.txt", file_content, "text/plain")}
        data = {"incident_id": str(incident_id), "description": "Test evidence"}
        resp = await ac.post("/evidence/upload", headers=headers, files=files, data=data)
        assert resp.status_code == 201
        ev = resp.json()
        assert ev["incident_id"] == incident_id
        assert ev["filename"] == "test.txt"
        assert "sha256" in ev and len(ev["sha256"]) == 64
        evidence_id = ev["id"]

        # Verify evidence
        resp = await ac.post(f"/evidence/{evidence_id}/verify", headers=headers)
        assert resp.status_code == 200
        verify = resp.json()
        assert verify["sha256"] == ev["sha256"]
        assert verify["matches"] is True

        # List evidence for incident
        resp = await ac.get(f"/evidence?incident_id={incident_id}", headers=headers)
        assert resp.status_code == 200
        lst = resp.json()
        assert isinstance(lst, list)
        assert any(e["id"] == evidence_id for e in lst)