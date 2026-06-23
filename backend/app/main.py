import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.api.v1 import router as api_router
from app.core.config import settings
from app.core.database import engine, Base
from app.core.redis import redis_client
from app.core.security_headers import SecurityHeadersMiddleware
from app.services.report_generator import validate_playwright_installation


# ---------------------------------------------------
# Logging
# ---------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("secaudit")


# ---------------------------------------------------
# Lifespan
# ---------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SecAudit Platform...")

    # Redis check
    try:
        await redis_client.ping()
        logger.info(
            "Redis connected (%s:%s)",
            settings.REDIS_HOST,
            settings.REDIS_PORT,
        )
    except Exception as e:
        logger.error("Redis connection failed: %s", e)

    # Database check with retry
    db_ok = False

    for i in range(10):
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))

                result = await conn.execute(
                    text(
                        """
                        SELECT tablename
                        FROM pg_catalog.pg_tables
                        WHERE schemaname='public'
                        AND tablename='users'
                        """
                    )
                )

                if result.scalar_one_or_none() is None:
                    raise RuntimeError(
                        "Database schema is missing required table 'users'. "
                        "Run 'docker compose exec api alembic upgrade head'."
                    )

            logger.info("Database connectivity and required tables verified")
            db_ok = True
            break

        except Exception as e:
            logger.warning("DB not ready (%s/10): %s", i + 1, e)
            await asyncio.sleep(2)

    if not db_ok:
        logger.error("Database failed to connect after retries")

    # Playwright check
    try:
        await validate_playwright_installation()
        logger.info("Playwright validation succeeded")
    except Exception as e:
        logger.warning("Playwright issue detected: %s", e)

    yield

    logger.info("Shutting down SecAudit Platform...")
    await redis_client.close()

# ---------------------------------------------------
# FastAPI app
# ---------------------------------------------------
app = FastAPI(
    title="SecAudit Platform API",
    description="Website Deployment Readiness & Security Audit Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ---------------------------------------------------
# Middleware
# ---------------------------------------------------
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    GZipMiddleware,
    minimum_size=1000,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------
# Request logging
# ---------------------------------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()

    response = await call_next(request)

    duration = time.time() - start

    logger.info(
        "%s %s -> %s (%.3fs)",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )

    return response


# ---------------------------------------------------
# Exception handlers
# ---------------------------------------------------
@app.exception_handler(OperationalError)
async def operational_error_handler(
    request: Request,
    exc: OperationalError,
):
    logger.error("DB operational error: %s", exc)

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database unavailable"},
    )


@app.exception_handler(DBAPIError)
async def dbapi_error_handler(
    request: Request,
    exc: DBAPIError,
):
    logger.error("DB API error: %s", exc)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Database error"},
    )


@app.exception_handler(Exception)
async def global_error_handler(
    request: Request,
    exc: Exception,
):
    logger.error(
        "Unhandled error: %s",
        exc,
        exc_info=True,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------
# Metrics
# ---------------------------------------------------
Instrumentator().instrument(app).expose(
    app,
    endpoint="/metrics",
)


# ---------------------------------------------------
# Routes
# ---------------------------------------------------
app.include_router(
    api_router,
    prefix="/api/v1",
)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "secaudit",
        "version": "1.0.0",
    }