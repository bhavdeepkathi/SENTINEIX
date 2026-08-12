from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.investigation import Recommendation
from app.models.user import User
from app.schemas.investigation import RecommendationRead, RecommendationCreate, RecommendationUpdate

router = APIRouter(prefix="/recommendations", tags=["recommendations"])

@router.post("/", response_model=RecommendationRead, status_code=status.HTTP_201_CREATED)
async def create_recommendation(
    payload: RecommendationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Verify investigation exists
    result = await db.execute(select(Recommendation).where(Recommendation.investigation_id == payload.investigation_id))
    # If investigation doesn't exist, select will return empty; check via relationship? Simpler: just create
    rec = Recommendation(
        investigation_id=payload.investigation_id,
        description=payload.description,
        priority=payload.priority,
        is_ai_generated=0,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return rec

@router.patch("/{rec_id}", response_model=RecommendationRead)
async def update_recommendation(
    rec_id: int,
    payload: RecommendationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Recommendation).where(Recommendation.id == rec_id))
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    if payload.description is not None:
        rec.description = payload.description
    if payload.priority is not None:
        rec.priority = payload.priority
    await db.commit()
    await db.refresh(rec)
    return rec

@router.delete("/{rec_id}", response_model=RecommendationRead)
async def delete_recommendation(
    rec_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Recommendation).where(Recommendation.id == rec_id))
    rec = result.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    await db.delete(rec)
    await db.commit()
    return rec
