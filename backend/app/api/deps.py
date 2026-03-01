"""API dependencies for dependency injection."""

from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.middleware.tenant import get_tenant_db
from app.core.redis import get_redis


# Type aliases for dependency injection
# SessionDep: Raw session without tenant context (for global tables like tenants, users)
SessionDep = Annotated[AsyncSession, Depends(get_session)]

# TenantSessionDep: Session with tenant context set via RLS (for tenant-scoped tables)
# Use this for all endpoints that access tenant-scoped data (investigations, entities, etc.)
TenantSessionDep = Annotated[AsyncSession, Depends(get_tenant_db)]

RedisDep = Annotated[Redis, Depends(get_redis)]


async def get_current_user() -> dict:
    """Get current authenticated user from Clerk.

    TODO: Implement Clerk authentication in Story 1.3
    """
    return {"id": "placeholder", "email": "placeholder@example.com"}


CurrentUserDep = Annotated[dict, Depends(get_current_user)]
