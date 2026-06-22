from fastapi import APIRouter

from app.api.v1.endpoints import auth, scans, findings, reports, organizations, users, webhooks, cicd

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(users.router, prefix="/users", tags=["Users"])
router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(findings.router, prefix="/findings", tags=["Findings"])
router.include_router(reports.router, prefix="/reports", tags=["Reports"])
router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
router.include_router(cicd.router, prefix="/cicd", tags=["CI/CD"])
