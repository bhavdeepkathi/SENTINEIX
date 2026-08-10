import pytest
import uuid
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_register_and_login():
    unique_email = f"test_{uuid.uuid4().hex}@example.com"
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # register
        resp = await ac.post("/auth/register", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == unique_email
        assert data["role"] == "analyst"
        # login
        resp = await ac.post("/auth/login", json={"email": unique_email, "password": "secret123"})
        assert resp.status_code == 200
        token_data = resp.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"