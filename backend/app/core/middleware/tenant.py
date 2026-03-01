"""Tenant context middleware for Row-Level Security.

Implements AC6 and AC7:
- AC6: PostgreSQL RLS policies use app.current_tenant session variable
- AC7: Database connection sets app.current_tenant before each request

This module provides:
- set_tenant_context: Sets the PostgreSQL session variable
- get_tenant_db: FastAPI dependency that provides tenant-scoped DB session
"""

from collections.abc import AsyncGenerator
from uuid import UUID

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_maker


async def set_tenant_context(session: AsyncSession, tenant_id: str) -> None:
    """Set PostgreSQL session variable for RLS.

    This function sets the app.current_tenant session variable that is used
    by RLS policies to filter data. Uses SET LOCAL so the setting is
    transaction-scoped and automatically cleaned up.

    Args:
        session: The async database session
        tenant_id: The tenant UUID as a string

    Example:
        async with async_session_maker() as session:
            await set_tenant_context(session, str(tenant_id))
            # Now all queries are automatically filtered by tenant_id
    """
    # Validate tenant_id is a valid UUID format to prevent SQL injection
    # (UUIDs can only contain hex chars and dashes)
    try:
        UUID(tenant_id)  # Validates format
    except ValueError as e:
        raise ValueError(f"Invalid tenant_id format: {tenant_id}") from e

    # SET commands don't support bound parameters in asyncpg, so we use
    # string formatting after validating the UUID format
    await session.execute(text(f"SET LOCAL app.current_tenant = '{tenant_id}'"))


async def get_tenant_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides a tenant-scoped database session.

    Extracts tenant_id from request.state (set by auth middleware from JWT claims)
    and sets the PostgreSQL session variable before yielding the session.

    Usage:
        @router.get("/investigations")
        async def list_investigations(db: AsyncSession = Depends(get_tenant_db)):
            # db session is automatically scoped to the request's tenant
            result = await db.exec(select(Investigation))
            return result.all()

    Args:
        request: The FastAPI request object with tenant_id in state

    Yields:
        AsyncSession: Database session with tenant context set

    Raises:
        ValueError: If tenant_id is not set in request.state
    """
    # Get tenant_id from request state (set by auth middleware)
    tenant_id: UUID | None = getattr(request.state, "tenant_id", None)

    if tenant_id is None:
        raise ValueError(
            "tenant_id not found in request.state. "
            "Ensure auth middleware sets request.state.tenant_id from JWT claims."
        )

    async with async_session_maker() as session:
        try:
            # Set tenant context for RLS
            await set_tenant_context(session, str(tenant_id))
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
