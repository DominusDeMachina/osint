"""Authentication middleware for JWT validation.

This module provides authentication utilities that can be used as middleware
or as FastAPI dependencies. The core JWT validation and user loading logic
is in app.api.deps to avoid duplication.

For most use cases, use CurrentUserDep from app.api.deps directly.
This module provides additional utilities for optional authentication.
"""

from fastapi import HTTPException, Request

from app.api.deps import get_current_user
from app.models.user import User


async def get_user_from_token(request: Request) -> User | None:
    """Extract and validate JWT, returning user if authenticated.

    Unlike get_current_user from deps, this returns None instead of
    raising an exception for unauthenticated requests. Useful for
    routes that have optional authentication.

    Args:
        request: The FastAPI request object

    Returns:
        User object if authenticated, None otherwise
    """
    try:
        return await get_current_user(request)
    except HTTPException:
        return None


async def require_auth(request: Request) -> User:
    """Dependency that requires authentication.

    This is an alias for get_current_user from deps.py.
    Prefer using CurrentUserDep directly for most use cases.

    Args:
        request: The FastAPI request object

    Returns:
        Authenticated User object

    Raises:
        HTTPException: 401 if not authenticated
    """
    return await get_current_user(request)
