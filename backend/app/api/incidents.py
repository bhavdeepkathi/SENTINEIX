from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.models.user import User
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentEvent
from app.models.alert import Alert
from app.models.log_event import LogEvent
from app.models.evidence import Evidence
from app.models.investigation import Investigation, Recommendation
from app.schemas.incident import IncidentRead, IncidentCreate, IncidentUpdate
from app.schemas.investigation import RecommendationCreate, RecommendationRead
from app.schemas.mitre import IncidentMitreMapping
from app.schemas.investigation import InvestigationRead
from app.services.correlation import CorrelationEngine
from app.services.mitre import MitreMapper
from app.services.report_generator import generate_incident_report
from app.services.ai_investigation import AIInvestigationService

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post("/correlate", response_model=List[IncidentRead], status_code=status.HTTP_201_CREATED)
async def correlate_alerts(
    since_minutes: int = Query(60, ge=1, le=1000000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    engine = CorrelationEngine(db)
    incidents = await engine.correlate_alerts(since_minutes)
    # Refresh to load relationships
    for inc in incidents:
        await db.refresh(inc)
    return incidents


@router.get("", response_model=List[IncidentRead])
async def list_incidents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(Incident).order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{incident_id}", response_model=IncidentRead)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
async def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/{incident_id}/timeline")
async def incident_timeline(
    incident_id: int,
    start_time: Optional[datetime] = Query(None, description="ISO8601 start timestamp"),
    end_time: Optional[datetime] = Query(None, description="ISO8601 end timestamp"),
    username: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Build base query
    stmt = (
        select(LogEvent, IncidentEvent.sequence_no)
        .join(IncidentEvent, LogEvent.id == IncidentEvent.log_event_id)
        .where(IncidentEvent.incident_id == incident_id)
    )
    # Apply filters
    if start_time:
        stmt = stmt.where(LogEvent.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(LogEvent.timestamp <= end_time)
    if username:
        stmt = stmt.where(LogEvent.username == username)
    if source_ip:
        stmt = stmt.where(LogEvent.source_ip == source_ip)
    if event_type:
        stmt = stmt.where(LogEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(LogEvent.severity == severity)
    # Order and pagination
    stmt = stmt.order_by(IncidentEvent.sequence_no).offset(skip).limit(limit)
    result = await db.execute(stmt)
    rows = result.all()
    timeline = [
        {
            "sequence_no": seq,
            "timestamp": log.timestamp.isoformat(),
            "source": log.source,
            "event_type": log.event_type,
            "username": log.username,
            "source_ip": log.source_ip,
            "hostname": log.hostname,
            "action": log.action,
            "status": log.status,
            "severity": log.severity,
        }
        for log, seq in rows
    ]
    return {"incident_id": incident_id, "timeline": timeline}


@router.get("/{incident_id}/mitre", response_model=List[IncidentMitreMapping])
async def incident_mitre(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    mapper = MitreMapper(db)
    mappings = await mapper.map_incident(incident)
    return mappings


@router.get("/{incident_id}/investigation", response_model=InvestigationRead)
async def get_investigation(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Investigation).where(Investigation.incident_id == incident_id))
    investigation = result.scalar_one_or_none()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    # Parse JSON fields
    import json
    def parse_json_field(value):
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return value
    investigation.attack_sequence = parse_json_field(investigation.attack_sequence)
    investigation.affected_assets = parse_json_field(investigation.affected_assets)
    investigation.mitre_techniques = parse_json_field(investigation.mitre_techniques)
    return investigation


@router.post("/{incident_id}/investigate", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    # fetch incident
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    service = AIInvestigationService(db)
    # Upsert investigation
    existing = await db.execute(select(Investigation).where(Investigation.incident_id == incident_id))
    investigation = existing.scalar_one_or_none()
    if investigation:
        # update existing
        new_inv = await service.run_investigation(incident, current_user.id)
        # update fields
        investigation.summary = new_inv.summary
        investigation.attack_type = new_inv.attack_type
        investigation.attack_sequence = new_inv.attack_sequence
        investigation.root_cause = new_inv.root_cause
        investigation.affected_assets = new_inv.affected_assets
        investigation.confidence = new_inv.confidence
        investigation.mitre_techniques = new_inv.mitre_techniques
        investigation.analyst_id = current_user.id
        # delete old recommendations and add new ones
        await db.execute(select(Recommendation).where(Recommendation.investigation_id == investigation.id))
        # simpler: delete old recommendations
        from app.models.investigation import Recommendation
        await db.execute(Recommendation.__table__.delete().where(Recommendation.investigation_id == investigation.id))
        for rec in new_inv.recommendations:
            db.add(rec)
    else:
        investigation = await service.run_investigation(incident, current_user.id)
    await db.commit()
    await db.refresh(investigation)
    # Parse JSON fields for response
    import json
    def parse_json_field(value):
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return value
    investigation.attack_sequence = parse_json_field(investigation.attack_sequence)
    investigation.affected_assets = parse_json_field(investigation.affected_assets)
    investigation.mitre_techniques = parse_json_field(investigation.mitre_techniques)
    return investigation


@router.get("/{incident_id}/report")
async def incident_report(
    incident_id: int,
    request: Request,
    token: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # If current_user not authenticated via header, try token query param
    if current_user is None:
        token = token or request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            try:
                from jose import jwt
                from app.core.config import get_settings
                settings = get_settings()
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
                email = payload.get("sub")
                if email:
                    result = await db.execute(select(User).where(User.email == email))
                    current_user = result.scalar_one_or_none()
            except Exception:
                current_user = None
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # timeline
    tl_stmt = (
        select(LogEvent, IncidentEvent.sequence_no)
        .join(IncidentEvent, LogEvent.id == IncidentEvent.log_event_id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.sequence_no)
    )
    tl_rows = (await db.execute(tl_stmt)).all()
    timeline = [
        {
            "sequence_no": seq,
            "timestamp": log.timestamp.isoformat(),
            "source": log.source,
            "event_type": log.event_type,
            "username": log.username,
            "source_ip": log.source_ip,
            "hostname": log.hostname,
            "action": log.action,
            "status": log.status,
            "severity": log.severity,
        }
        for log, seq in tl_rows
    ]

    # fetch incident (needed for report)
    inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = inc_result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # alerts
    al_stmt = select(Alert).where(Alert.incident_id == incident_id)
    alerts = (await db.execute(al_stmt)).scalars().all()
    alerts_data = [
        {
            "id": a.id,
            "title": a.title,
            "description": a.description,
            "severity": a.severity.value if a.severity else None,
            "status": a.status.value if a.status else None,
            "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]

    # evidence
    ev_stmt = select(Evidence).where(Evidence.incident_id == incident_id)
    evidence = (await db.execute(ev_stmt)).scalars().all()
    evidence_data = [
        {
            "id": e.id,
            "filename": e.filename,
            "file_type": e.file_type,
            "file_size": e.file_size,
            "sha256": e.sha256,
            "uploaded_by": e.uploaded_by,
            "uploaded_at": e.uploaded_at.isoformat(),
            "description": e.description,
        }
        for e in evidence
    ]

    # investigation
    inv_stmt = select(Investigation).where(Investigation.incident_id == incident_id)
    investigation = (await db.execute(inv_stmt)).scalar_one_or_none()
    investigation_data = None
    recommendations_data = []
    if investigation:
        investigation_data = {
            "id": investigation.id,
            "summary": investigation.summary,
            "attack_type": investigation.attack_type,
            "attack_sequence": investigation.attack_sequence,
            "root_cause": investigation.root_cause,
            "affected_assets": investigation.affected_assets,
            "confidence": investigation.confidence,
            "mitre_techniques": investigation.mitre_techniques,
        }
        rec_stmt = select(Recommendation).where(Recommendation.investigation_id == investigation.id)
        recommendations = (await db.execute(rec_stmt)).scalars().all()
        recommendations_data = [
            {
                "id": r.id,
                "description": r.description,
                "priority": r.priority,
                "is_ai_generated": bool(r.is_ai_generated),
            }
            for r in recommendations
        ]

    # mitre
    mitre_stmt = select(
        __import__('app.models.mitre', fromlist=['MitreTechnique']).MitreTechnique.technique_id,
        __import__('app.models.mitre', fromlist=['MitreTechnique']).MitreTechnique.name,
        __import__('app.models.mitre', fromlist=['MitreTechnique']).MitreTechnique.tactic,
        __import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre.c.confidence,
        __import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre.c.evidence_ref,
    ).join(
        __import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre,
        __import__('app.models.mitre', fromlist=['MitreTechnique']).MitreTechnique.technique_id == __import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre.c.technique_id
    ).where(__import__('app.models.mitre', fromlist=['incident_mitre']).incident_mitre.c.incident_id == incident_id)
    mitre_rows = (await db.execute(mitre_stmt)).all()
    mitre_data = [
        {
            "technique_id": row[0],
            "name": row[1],
            "tactic": row[2],
            "confidence": row[3],
            "evidence_ref": row[4],
        }
        for row in mitre_rows
    ]

    incident_dict = {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value if incident.severity else None,
        "status": incident.status.value if incident.status else None,
        "risk_score": incident.risk_score,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }

    pdf_bytes = generate_incident_report(
        incident=incident_dict,
        timeline=timeline,
        alerts=alerts_data,
        evidence=evidence_data,
        investigation=investigation_data,
        mitre=mitre_data,
        recommendations=recommendations_data,
    )

    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}_report.pdf"})

@router.post("/{incident_id}/recommendations", response_model=RecommendationRead, status_code=status.HTTP_201_CREATED)
async def add_manual_recommendation(
    incident_id: int,
    payload: RecommendationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "investigator"))
):
    # Ensure incident exists
    inc_res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = inc_res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Find existing investigation or create placeholder
    inv_res = await db.execute(select(Investigation).where(Investigation.incident_id == incident_id))
    investigation = inv_res.scalar_one_or_none()
    if not investigation:
        investigation = Investigation(incident_id=incident_id)
        db.add(investigation)
        await db.flush()
    rec = Recommendation(
        investigation_id=investigation.id,
        description=payload.description,
        priority=payload.priority,
        is_ai_generated=0,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return rec

@router.get("/{incident_id}/recommendations", response_model=List[RecommendationRead])
async def get_incident_recommendations(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # verify incident exists
    inc_res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = inc_res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    # find investigation, if any
    inv_res = await db.execute(select(Investigation).where(Investigation.incident_id == incident_id))
    investigation = inv_res.scalar_one_or_none()
    if not investigation:
        return []
    rec_res = await db.execute(select(Recommendation).where(Recommendation.investigation_id == investigation.id))
    recs = rec_res.scalars().all()
    return recs