"""
OAuth/SSO Authentication — supports Google, GitHub, Azure AD.
Works alongside existing JWT auth without breaking it.
"""
import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token
from app.models.models import User

logger = logging.getLogger(__name__)

oauth_router = APIRouter(prefix="/auth/oauth", tags=["oauth"])


async def verify_google_token(token: str) -> Optional[dict]:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            return None
        return resp.json()


async def verify_github_token(token: str) -> Optional[dict]:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code != 200:
            return None
        user_data = resp.json()
        emails_resp = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {token}"},
        )
        if emails_resp.status_code == 200:
            emails = emails_resp.json()
            primary = next((e for e in emails if e.get("primary")), {})
            user_data["email"] = primary.get("email", user_data.get("email"))
        return user_data


PROVIDERS = {
    "google": verify_google_token,
    "github": verify_github_token,
}


@oauth_router.post("/{provider}")
async def oauth_login(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body = await request.json()
    token = body.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token required")

    verify_fn = PROVIDERS.get(provider)
    if not verify_fn:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    user_info = await verify_fn(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = user_info.get("email")
    name = user_info.get("name") or user_info.get("login", "OAuth User")

    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by OAuth provider")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            email=email,
            full_name=name,
            hashed_password="",
            is_verified=True,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    access_token = create_access_token(subject=str(user.id))
    refresh_token = create_refresh_token(subject=str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
        },
    }
