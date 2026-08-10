import asyncio
import sys
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_upload_logs_json_and_csv():
    unique_email = f"test_{uuid.uuid4().hex}@example.com"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # register
        resp = await ac.post("/auth/register", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 201
        # login
        resp = await ac.post("/auth/login", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Test JSON upload
        log_content = '''[
            {"timestamp": "2024-01-10T10:01:00Z", "source": "test", "event_type": "login", "username": "user1", "source_ip": "1.2.3.4", "severity": "info"},
            {"timestamp": "2024-01-10T10:02:00Z", "source": "test", "event_type": "logout", "username": "user1", "source_ip": "1.2.3.4", "severity": "info"}
        ]'''
        files = {"file": ("test.json", log_content, "application/json")}
        resp = await ac.post("/logs/upload", files=files, headers=headers)
        assert resp.status_code == 201
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 2
        for entry in data:
            assert "id" in entry
            assert entry["source"] == "test"
            assert entry["username"] == "user1"

        # Test CSV upload
        csv_content = """timestamp,source,event_type,username,source_ip,severity
2024-01-10T10:01:00Z,test,login,user1,1.2.3.4,info
2024-01-10T10:02:00Z,test,logout,user1,1.2.3.4,info
"""
        files = {"file": ("test.csv", csv_content, "text/csv")}
        resp = await ac.post("/logs/upload", files=files, headers=headers)
        assert resp.status_code == 201
        data = resp.json()
        assert len(data) == 2