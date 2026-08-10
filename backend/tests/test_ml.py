import asyncio
import sys
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_ml_detect():
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

        # Features: hour, failed_logins, success_logins, privileged_cmds, data_mb, unique_ips, user_id
        payload = {"features": [10.0, 5.0, 1.0, 2.0, 200.0, 3.0, 42.0]}
        resp = await ac.post("/ml/detect", json=payload, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "isolation_forest" in data
        assert "random_forest" in data
        # xgboost may be None
        assert "xgboost" in data
        # Check structure
        iso = data["isolation_forest"]
        assert "anomaly_score" in iso
        assert "is_anomaly" in iso
        rf = data["random_forest"]
        assert "malicious_probability" in rf
        assert "prediction" in rf