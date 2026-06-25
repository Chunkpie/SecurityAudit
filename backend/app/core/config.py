import logging
import secrets
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import field_validator, model_validator

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SecAudit Platform"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_urlsafe(64)
    API_V1_STR: str = "/api/v1"

    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "secaudit"
    POSTGRES_USER: str = "secaudit"
    POSTGRES_PASSWORD: str = "changeme"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def SYNC_DATABASE_URL(self) -> str:
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def REDIS_URL_REDACTED(self) -> str:
        auth = ":***@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def DATABASE_URL_REDACTED(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:***"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # JWT
    JWT_SECRET_KEY: str = secrets.token_urlsafe(64)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:80"]

    # Storage
    REPORTS_DIR: str = "/app/reports"
    UPLOADS_DIR: str = "/app/uploads"
    SCREENSHOTS_DIR: str = "/app/screenshots"

    # Celery
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    SCAN_RATE_LIMIT_PER_HOUR: int = 10

    # Scan settings
    SCAN_TIMEOUT_SECONDS: int = 3600
    MAX_CONCURRENT_SCANS: int = 5

    # Ollama (optional)
    OLLAMA_ENABLED: bool = False
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    # Email (optional)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: str = "noreply@secaudit.local"

    # Feature flags
    ENABLE_SUBDOMAIN_DISCOVERY: bool = True
    ENABLE_SOURCE_CODE_SCAN: bool = True
    ENABLE_SCHEDULED_SCANS: bool = True

    # False Positive Reduction
    ENABLE_FINDING_CORRELATION: bool = True
    ENABLE_FINDING_SUPPRESSION: bool = False
    ENABLE_FINDING_VALIDATION: bool = False
    CORRELATION_MIN_SOURCES: int = 2
    CONFIDENCE_CONFIRMED_THRESHOLD: float = 0.7
    CONFIDENCE_SUSPICIOUS_THRESHOLD: float = 0.4

    @model_validator(mode="after")
    def validate_celery_settings(self):
        if self.CELERY_BROKER_URL is None:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if self.CELERY_RESULT_BACKEND is None:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL

        if "localhost" in self.REDIS_URL or "127.0.0.1" in self.REDIS_URL:
            message = (
                "Redis is configured to use localhost. In Docker this should use service name 'redis' instead. "
                "Set REDIS_HOST=redis or CELERY_BROKER_URL/CELERY_RESULT_BACKEND to redis://redis:6379/0."
            )
            if self.ENVIRONMENT.lower() == "production":
                raise ValueError(message)
            logger.warning(message)

        if "localhost" in (self.CELERY_BROKER_URL or "") or "127.0.0.1" in (self.CELERY_BROKER_URL or ""):
            message = (
                "Celery broker or backend is configured to use localhost. In Docker this should use service name 'redis'. "
                "Set REDIS_HOST=redis or CELERY_BROKER_URL/CELERY_RESULT_BACKEND to redis://redis:6379/0."
            )
            if self.ENVIRONMENT.lower() == "production":
                raise ValueError(message)
            logger.warning(message)

        if self.CELERY_BROKER_URL != self.CELERY_RESULT_BACKEND:
            logger.info(
                "Celery broker and result backend differ. broker=%s backend=%s",
                self.CELERY_BROKER_URL,
                self.CELERY_RESULT_BACKEND,
            )
        return self

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
