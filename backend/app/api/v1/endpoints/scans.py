import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import Scan, ScanStatus, Finding, Organization, OrganizationMember, UserRole, User
from app.schemas.schemas import ScanCreate, ScanResponse, ScanListResponse
from app.workers.tasks import run_scan_task

router = APIRouter()
logger = logging.getLogger(__name__)


def extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]


async def verify_org_access(org_id: UUID, user: User, db: AsyncSession) -> Organization:
    result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    member_result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id,
        )
    )
    if not member_result.scalar_one_or_none() and not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return org


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_in: ScanCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org = await verify_org_access(scan_in.organization_id, current_user, db)

    scan = Scan(
        organization_id=scan_in.organization_id,
        created_by=current_user.id,
        target_url=scan_in.target_url,
        target_domain=extract_domain(scan_in.target_url),
        scan_type=scan_in.scan_type,
        scan_config=scan_in.scan_config or {},
        consent_confirmed=scan_in.consent_confirmed,
        consent_timestamp=datetime.now(timezone.utc),
        consent_ip=request.client.host if request.client else None,
        scheduled=scan_in.scheduled,
        schedule_frequency=scan_in.schedule_frequency,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()

    try:
        task = run_scan_task.delay(str(scan.id))
        logger.info(f"Queued scan {scan.id} as task {task.id}")
    except Exception as e:
        logger.error(f"Failed to queue scan {scan.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue scan task",
        )

    logger.info(f"Scan created: {scan.id} for {scan.target_url}")
    return scan


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    organization_id: UUID,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[ScanStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await verify_org_access(organization_id, current_user, db)

    query = select(Scan).where(Scan.organization_id == organization_id)
    if status:
        query = query.where(Scan.status == status)

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar()

    query = query.order_by(desc(Scan.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(items=scans, total=total, page=page, per_page=per_page)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await verify_org_access(scan.organization_id, current_user, db)
    return scan


@router.post("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await verify_org_access(scan.organization_id, current_user, db)

    if scan.status not in [ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan cannot be stopped")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    return scan


@router.get("/{scan_id}/summary")
async def get_scan_summary(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await verify_org_access(scan.organization_id, current_user, db)

    findings_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == scan_id, Finding.is_false_positive == False)
        .group_by(Finding.severity)
    )
    severity_counts = {row[0]: row[1] for row in findings_result.all()}

    return {
        "scan_id": str(scan_id),
        "status": scan.status,
        "verdict": scan.verdict,
        "security_score": scan.security_score,
        "target_url": scan.target_url,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "findings_summary": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
    }
