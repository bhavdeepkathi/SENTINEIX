from fastapi import FastAPI
from app.api import auth, logs, alerts, ml, incidents, evidence, investigations
from app.core.database import init_db
from app.models.user import Role
from app.core.database import AsyncSessionLocal
from sqlalchemy import select

app = FastAPI(title="SentinelX API")

app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(ml.router)
app.include_router(incidents.router)
app.include_router(evidence.router)
app.include_router(investigations.router)

@app.on_event("startup")
async def on_startup():
    await init_db()
    # seed roles if not exist
    async with AsyncSessionLocal() as session:
        for role_name in ("admin", "analyst", "investigator"):
            result = await session.execute(select(Role).where(Role.name == role_name))
            if not result.scalar_one_or_none():
                session.add(Role(name=role_name))
        await session.commit()

@app.get("/health")
async def health():
    return {"status": "ok"}