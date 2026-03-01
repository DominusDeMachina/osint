"""API dependencies for dependency injection."""

from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.redis import get_redis


# Type aliases for dependency injection
SessionDep = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]


async def get_current_user() -> dict:
    """Get current authenticated user from Clerk.

    TODO: Implement Clerk authentication in Story 1.3
    """
    return {"id": "placeholder", "email": "placeholder@example.com"}


CurrentUserDep = Annotated[dict, Depends(get_current_user)]
