from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, conlist
from typing import List
from app.core.dependencies import get_current_user, require_role
from app.models.user import User
from app.services.ml_detection import ml_engine

router = APIRouter(prefix="/ml", tags=["ml"])

class FeaturesInput(BaseModel):
    # Expect exactly 7 features in order
    features: conlist(float, min_length=7, max_length=7)

class MLResult(BaseModel):
    isolation_forest: dict
    random_forest: dict
    xgboost: dict | None = None

@router.post("/detect", response_model=MLResult, status_code=status.HTTP_200_OK)
async def ml_detect(
    payload: FeaturesInput,
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    try:
        result = ml_engine.predict(payload.features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML inference failed: {e}")
    return result