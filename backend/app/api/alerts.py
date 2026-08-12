from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.models.user import User
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.schemas.alert import AlertRead, AlertUpdate
from app.services.detection import RuleEngine


router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("/run-detection", response_model=List[AlertRead], status_code=status.HTTP_201_CREATED)
async def run_detection(
    since_minutes: int = Query(60, ge=1, le=1000000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    engine = RuleEngine(db)
    alerts = await engine.run_all_rules(since_minutes)
    await db.commit()
    # refresh to get IDs
    for a in alerts:
        await db.refresh(a)
    return alerts


@router.get("", response_model=List[AlertRead])
async def list_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: AlertSeverity | None = None,
    status: AlertStatus | None = None,
    incident_id: int | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(Alert).order_by(Alert.created_at.desc()).offset(skip).limit(limit)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    if incident_id:
        stmt = stmt.where(Alert.incident_id == incident_id)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertRead)
async def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(alert, field, value)
    await db.commit()
    await db.refresh(alert)
    return alert