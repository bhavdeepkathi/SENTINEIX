from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.log_event import LogEvent
from app.schemas.log_event import LogEventRead
from app.services.log_normalizer import LogNormalizer
from typing import List, Optional


router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/upload", response_model=List[LogEventRead], status_code=status.HTTP_201_CREATED)
async def upload_logs(
    file: UploadFile = File(...),
    fmt: Optional[str] = Form(None),  # e.g., json, csv, linux_auth, windows_security, generic
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    content = await file.read()
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")

    # Normalize
    events = LogNormalizer.normalize(text, fmt or 'auto')
    if not events:
        raise HTTPException(status_code=400, detail="No valid log entries found")

    # Persist
    db_events = []
    for ev in events:
        db_ev = LogEvent(**ev.model_dump())
        db.add(db_ev)
        db_events.append(db_ev)
    await db.commit()
    for ev in db_events:
        await db.refresh(ev)

    return db_events


@router.get("", response_model=List[LogEventRead])
async def list_logs(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from sqlalchemy import select
    result = await db.execute(select(LogEvent).offset(skip).limit(limit).order_by(LogEvent.timestamp.desc()))
    return result.scalars().all()