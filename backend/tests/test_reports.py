"""Tests for report generation and export endpoints."""
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.exc import MultipleResultsFound
from sqlalchemy import select

from app.main import app
from app.models.models import (
    User, Organization, OrganizationMember, Scan, Finding, Report,
    ScanStatus, UserRole, FindingSeverity
)
from app.core.database import Base, get_db
from app.core.config import settings
from app.services.report_generator import generate_pdf_report


@pytest.fixture
async def db_session():
    """Create an in-memory SQLite async session for tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
async def test_user(db_session: AsyncSession):
    """Create a test user."""
    user = User(
        id=uuid.uuid4(),
        email="test@example.com",
        hashed_password="hashed_password",
        full_name="Test User",
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture
async def test_organization(db_session: AsyncSession, test_user: User):
    """Create a test organization."""
    org = Organization(
        id=uuid.uuid4(),
        name="Test Org",
        slug="test-org",
        plan="premium",
    )
    db_session.add(org)
    await db_session.commit()
    
    member = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=org.id,
        user_id=test_user.id,
        role=UserRole.OWNER,
    )
    db_session.add(member)
    await db_session.commit()
    return org


@pytest.fixture
async def test_scan(db_session: AsyncSession, test_organization: Organization, test_user: User):
    """Create a completed test scan."""
    scan = Scan(
        id=uuid.uuid4(),
        organization_id=test_organization.id,
        created_by=test_user.id,
        target_url="https://example.com",
        target_domain="example.com",
        scan_type="full",
        status=ScanStatus.COMPLETED,
        security_score=85.0,
        verdict="GO",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    await db_session.commit()
    return scan


@pytest.fixture
async def test_findings(db_session: AsyncSession, test_scan: Scan):
    """Create test findings."""
    findings = [
        Finding(
            id=uuid.uuid4(),
            scan_id=test_scan.id,
            title="Missing Security Header",
            severity=FindingSeverity.HIGH,
            category="Headers",
            description="X-Frame-Options header is missing",
            impact="Clickjacking vulnerability",
            remediation="Add X-Frame-Options: DENY header",
        ),
        Finding(
            id=uuid.uuid4(),
            scan_id=test_scan.id,
            title="Weak SSL Configuration",
            severity=FindingSeverity.MEDIUM,
            category="SSL/TLS",
            description="SSL version 3.0 is enabled",
            impact="Man-in-the-middle attacks",
            remediation="Disable SSL 3.0 and use TLS 1.2+",
        ),
    ]
    for finding in findings:
        db_session.add(finding)
    await db_session.commit()
    return findings


@pytest.mark.asyncio
async def test_get_existing_report_no_rows(db_session: AsyncSession):
    """Test getting existing report when none exists returns None."""
    from app.api.v1.endpoints.reports import get_existing_report
    
    scan_id = uuid.uuid4()
    report = await get_existing_report(db_session, scan_id, "pdf")
    assert report is None


@pytest.mark.asyncio
async def test_get_existing_report_single_row(db_session: AsyncSession, test_scan: Scan):
    """Test getting existing report when one exists."""
    from app.api.v1.endpoints.reports import get_existing_report
    
    # Create a report
    report = Report(
        id=uuid.uuid4(),
        scan_id=test_scan.id,
        report_type="pdf",
        file_path="/path/to/report.pdf",
        file_size=1024,
    )
    db_session.add(report)
    await db_session.commit()
    
    # Retrieve it
    result = await get_existing_report(db_session, test_scan.id, "pdf")
    assert result is not None
    assert result.id == report.id
    assert result.report_type == "pdf"


@pytest.mark.asyncio
async def test_get_existing_report_returns_latest(
    db_session: AsyncSession,
    test_scan: Scan,
):
    """Test that get_existing_report returns the latest report when multiple exist in DB."""
    from app.api.v1.endpoints.reports import get_existing_report
    
    # Create multiple reports (simulating old DB state before unique constraint)
    old_report = Report(
        id=uuid.uuid4(),
        scan_id=test_scan.id,
        report_type="pdf",
        file_path="/path/to/old.pdf",
        file_size=512,
        generated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add(old_report)
    await db_session.commit()
    
    # Disable unique constraint check for this test
    new_report = Report(
        id=uuid.uuid4(),
        scan_id=test_scan.id,
        report_type="pdf",
        file_path="/path/to/new.pdf",
        file_size=2048,
        generated_at=datetime(2024, 12, 22, tzinfo=timezone.utc),
    )
    db_session.add(new_report)
    await db_session.commit()
    
    # Should return the latest one
    result = await get_existing_report(db_session, test_scan.id, "pdf")
    assert result.id == new_report.id
    assert result.file_size == 2048


@pytest.mark.asyncio
async def test_get_scan_with_findings_scan_not_found(db_session: AsyncSession):
    """Test error when scan doesn't exist."""
    from app.api.v1.endpoints.reports import get_scan_with_findings
    from fastapi import HTTPException
    
    with pytest.raises(HTTPException) as exc_info:
        await get_scan_with_findings(uuid.uuid4(), db_session)
    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_get_scan_with_findings_not_completed(db_session: AsyncSession, test_scan: Scan):
    """Test error when scan is not completed."""
    from app.api.v1.endpoints.reports import get_scan_with_findings
    from fastapi import HTTPException
    
    test_scan.status = ScanStatus.PENDING
    await db_session.commit()
    
    with pytest.raises(HTTPException) as exc_info:
        await get_scan_with_findings(test_scan.id, db_session)
    assert exc_info.value.status_code == 400
    assert "not completed" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_get_scan_with_findings_success(db_session: AsyncSession, test_scan: Scan, test_findings):
    """Test successful retrieval of scan with findings."""
    from app.api.v1.endpoints.reports import get_scan_with_findings
    
    scan, findings = await get_scan_with_findings(test_scan.id, db_session)
    assert scan.id == test_scan.id
    assert len(findings) == 2
    assert findings[0].title == "Missing Security Header"


@pytest.mark.asyncio
async def test_pdf_generation_mocked(db_session: AsyncSession, test_scan: Scan, test_findings):
    """Test PDF report generation with mocked Playwright."""
    with patch(
        "app.services.report_generator.generate_pdf_report",
        new_callable=AsyncMock,
    ) as mock_gen:
        mock_gen.return_value = "/tmp/test_report.pdf"
        with patch("os.path.exists", return_value=True):
            with patch("os.path.getsize", return_value=5000):
                result = await generate_pdf_report(test_scan, test_findings)
                assert result == "/tmp/test_report.pdf"
                mock_gen.assert_called_once()


@pytest.mark.asyncio
async def test_report_caching(db_session: AsyncSession, test_scan: Scan, test_findings):
    """Test that reports are cached after generation."""
    from app.api.v1.endpoints.reports import get_existing_report
    
    # Initially no report
    assert await get_existing_report(db_session, test_scan.id, "pdf") is None
    
    # Create and cache a report
    report = Report(
        id=uuid.uuid4(),
        scan_id=test_scan.id,
        report_type="pdf",
        file_path="/tmp/cached.pdf",
        file_size=5000,
    )
    db_session.add(report)
    await db_session.commit()
    
    # Now it should be cached
    cached = await get_existing_report(db_session, test_scan.id, "pdf")
    assert cached is not None
    assert cached.id == report.id


@pytest.mark.asyncio
async def test_report_unique_constraint():
    """Test that UniqueConstraint prevents duplicate reports per scan per type."""
    # This would be enforced by the database after migration
    # Here we verify the model has the constraint defined
    from app.models.models import Report
    
    table_args = Report.__table_args__
    assert isinstance(table_args, tuple)
    
    # Find UniqueConstraint in table_args
    has_unique_constraint = any(
        hasattr(arg, "columns") and "scan_id" in str(arg.columns)
        for arg in table_args
        if hasattr(arg, "name") and "scan_type" in arg.name
    )
    assert has_unique_constraint, "UniqueConstraint on (scan_id, report_type) not found"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
