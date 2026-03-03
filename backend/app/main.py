"""OSINT Platform Backend - FastAPI Application Entry Point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.auth import router as auth_router
from app.api.v1.gdpr import admin_router as gdpr_admin_router
from app.api.v1.gdpr import router as gdpr_router
from app.api.v1.investigations import permissions_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.webhooks.clerk import router as clerk_webhook_router
from app.core.config import settings
from app.core.middleware.rate_limit import RateLimitMiddleware
from app.core.redis import get_redis_client


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup/shutdown events."""
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title="OSINT Platform API",
    description="Open Source Intelligence Platform for investigative research",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Rate Limiting (AC3, AC4, AC5, AC9, AC10)
# Note: Middleware stack runs in reverse order - last added runs first
# So RateLimitMiddleware runs after CORS
app.add_middleware(RateLimitMiddleware, redis=get_redis_client())


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Health check endpoint for monitoring and orchestration."""
    return {"status": "healthy", "version": "0.1.0"}


@app.get("/api/v1/health", tags=["Health"])
async def api_health_check() -> dict[str, str]:
    """API v1 health check endpoint."""
    return {"status": "healthy", "api_version": "v1"}


# Include API routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(permissions_router, prefix="/api/v1")
app.include_router(clerk_webhook_router, prefix="/api/v1")
app.include_router(gdpr_router, prefix="/api/v1")
app.include_router(gdpr_admin_router, prefix="/api/v1")
