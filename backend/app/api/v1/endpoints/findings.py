from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import Finding, FindingSeverity, Scan, User
from app.schemas.schemas import FindingResponse, FindingListResponse, FindingUpdate

router = APIRouter()


@router.get("/", response_model=FindingListResponse)
async def list_findings(
    scan_id: UUID,
    severity: Optional[FindingSeverity] = None,
    category: Optional[str] = None,
    is_resolved: Optional[bool] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify scan access
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Finding).where(Finding.scan_id == scan_id, Finding.is_false_positive == False)
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if is_resolved is not None:
        query = query.where(Finding.is_resolved == is_resolved)

    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    severity_counts_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == scan_id, Finding.is_false_positive == False)
        .group_by(Finding.severity)
    )
    counts = {row[0]: row[1] for row in severity_counts_result.all()}

    items_result = await db.execute(
        query.offset((page - 1) * per_page).limit(per_page)
    )
    items = items_result.scalars().all()

    return FindingListResponse(
        items=items,
        total=total,
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        info=counts.get("info", 0),
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    update: FindingUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if update.is_false_positive is not None:
        finding.is_false_positive = update.is_false_positive
    if update.is_resolved is not None:
        from datetime import datetime, timezone
        finding.is_resolved = update.is_resolved
        finding.resolved_at = datetime.now(timezone.utc) if update.is_resolved else None
    return finding
