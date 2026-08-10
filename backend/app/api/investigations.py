from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.investigation import Investigation, Recommendation
from app.schemas.investigation import RecommendationRead

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("/{investigation_id}/recommendations", response_model=List[RecommendationRead])
async def get_recommendations(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
    investigation = result.scalar_one_or_none()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    # load recommendations
    result = await db.execute(select(Recommendation).where(Recommendation.investigation_id == investigation_id))
    recs = result.scalars().all()
    return recs