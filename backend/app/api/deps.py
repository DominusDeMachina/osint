"""API dependencies for dependency injection."""

from typing import Annotated

from fastapi import Depends, HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.database import async_session_maker, get_session
from app.core.middleware.tenant import get_tenant_db
from app.core.redis import get_redis
from app.core.security.clerk import validate_clerk_token
from app.models.user import TenantMembership, User


# Type aliases for dependency injection
# SessionDep: Raw session without tenant context (for global tables like tenants, users)
SessionDep = Annotated[AsyncSession, Depends(get_session)]

# TenantSessionDep: Session with tenant context set via RLS (for tenant-scoped tables)
# Use this for all endpoints that access tenant-scoped data (investigations, entities, etc.)
TenantSessionDep = Annotated[AsyncSession, Depends(get_tenant_db)]

RedisDep = Annotated[Redis, Depends(get_redis)]


async def get_current_user(request: Request) -> User:
    """Get current authenticated user from Clerk JWT.

    Extracts Bearer token from Authorization header, validates it using
    Clerk's JWKS, and loads the user from the database.

    Args:
        request: The FastAPI request object

    Returns:
        Authenticated User object

    Raises:
        HTTPException: 401 if not authenticated or user not found
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.replace("Bearer ", "")

    try:
        claims = await validate_clerk_token(token)
    except ValueError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    # Load user from database
    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.clerk_id == claims.sub))
        user = result.scalar_one_or_none()

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User not found in database",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="User account is disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user's primary tenant membership and set on request state
        membership_result = await session.execute(
            select(TenantMembership).where(TenantMembership.user_id == user.id)
        )
        membership = membership_result.scalar_one_or_none()

        # Set request state for tenant context
        request.state.user = user
        request.state.user_id = user.id
        request.state.clerk_id = claims.sub

        if membership:
            request.state.tenant_id = membership.tenant_id
            request.state.user_role = membership.role
        else:
            request.state.tenant_id = None
            request.state.user_role = None

        return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]
