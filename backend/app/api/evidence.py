import os
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.models.user import User
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.schemas.evidence import EvidenceRead, EvidenceVerify
from app.services.forensic import compute_sha256, verify_sha256

router = APIRouter(prefix="/evidence", tags=["evidence"])

# Directory to store uploaded evidence files
EVIDENCE_DIR = Path(__file__).resolve().parents[3] / "evidence_store"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/upload", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    incident_id: int = Form(...),
    description: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    # Verify incident exists
    inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = inc_result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Save file to disk with a safe name
    safe_filename = f"{incident_id}_{current_user.id}_{file.filename}"
    dest_path = EVIDENCE_DIR / safe_filename
    with dest_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Compute hash
    sha256_hash = compute_sha256(dest_path)
    file_size = dest_path.stat().st_size
    file_type = file.content_type

    # Check duplicate hash
    existing = await db.execute(select(Evidence).where(Evidence.sha256 == sha256_hash))
    if existing.scalar_one_or_none():
        # Remove the newly saved duplicate file
        dest_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Evidence with same hash already exists")

    evidence = Evidence(
        incident_id=incident_id,
        filename=file.filename,
        file_type=file_type,
        file_size=file_size,
        sha256=sha256_hash,
        uploaded_by=current_user.id,
        description=description,
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)
    return evidence


@router.get("", response_model=List[EvidenceRead])
async def list_evidence(
    incident_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(Evidence).order_by(Evidence.uploaded_at.desc()).offset(skip).limit(limit)
    if incident_id:
        stmt = stmt.where(Evidence.incident_id == incident_id)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{evidence_id}", response_model=EvidenceRead)
async def get_evidence(
    evidence_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.post("/{evidence_id}/verify", response_model=EvidenceVerify)
async def verify_evidence(
    evidence_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    file_path = EVIDENCE_DIR / f"{evidence.incident_id}_{evidence.uploaded_by}_{evidence.filename}"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing on disk")

    matches = verify_sha256(file_path, evidence.sha256)
    return EvidenceVerify(sha256=evidence.sha256, matches=matches)