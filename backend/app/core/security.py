import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# Use PBKDF2-SHA256 to avoid bcrypt's 72-byte limit and provide a secure default
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # bcrypt has a 72-byte maximum — ensure we compare using the same truncation
    try:
        pw = plain_password
        pwb = pw.encode("utf-8") if isinstance(pw, str) else pw
        if len(pwb) > 72:
            pw = pwb[:72].decode("utf-8", errors="ignore")
    except Exception:
        pw = plain_password
    return pwd_context.verify(pw, hashed_password)


def get_password_hash(password: str) -> str:
    # bcrypt backend (used by passlib) cannot handle passwords longer than 72 bytes.
    # Truncate to 72 bytes using utf-8 encoding to avoid ValueError.
    try:
        pwb = password.encode("utf-8") if isinstance(password, str) else password
        if len(pwb) > 72:
            password = pwb[:72].decode("utf-8", errors="ignore")
    except Exception:
        pass
    return pwd_context.hash(password)


def create_access_token(subject: Union[str, int], expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire, "sub": str(subject), "type": "access"}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: Union[str, int]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def generate_api_key() -> str:
    return f"sak_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()
