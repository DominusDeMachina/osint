"""RBAC FastAPI dependencies for authorization.

Implements Story 1.4 AC1, 2, 3, 7: RBAC decorators and dependencies
that integrate with existing Clerk auth from Story 1.3.

Usage:
    # Require view permission (owner, analyst, viewer)
    @router.get("/investigations/{investigation_id}")
    async def get_investigation(
        investigation_id: UUID,
        user: User = Depends(RequireInvestigationRole(["owner", "analyst", "viewer"])),
    ):
        ...

    # Require edit permission (owner, analyst)
    @router.patch("/investigations/{investigation_id}")
    async def update_investigation(
        investigation_id: UUID,
        user: User = Depends(RequireInvestigationRole(["owner", "analyst"])),
    ):
        ...

    # Require owner for permission management
    @router.post("/investigations/{investigation_id}/permissions")
    async def grant_permission(
        investigation_id: UUID,
        user: User = Depends(RequireInvestigationRole(["owner"])),
    ):
        ...
"""

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Path, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole
from app.services.permissions import PermissionService


if TYPE_CHECKING:
    pass


async def get_current_user_for_rbac(request: Request) -> User:
    """Get current user for RBAC checks.

    This is a wrapper to avoid circular imports with api.deps.
    It expects the user to already be set in request.state by
    the auth middleware/dependency.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
        )
    return user


async def get_session_for_rbac(
    request: Request,  # noqa: ARG001
) -> AsyncGenerator[AsyncSession, None]:
    """Get database session for RBAC checks.

    Creates a new session for permission queries with proper lifecycle management.
    """
    from app.core.database import async_session_maker  # noqa: PLC0415

    async with async_session_maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


class RequireGlobalRole:
    """Dependency that checks global tenant-level role.

    Use for endpoints that require tenant-level admin access,
    not specific investigation permissions.

    Args:
        allowed_roles: List of roles that can access the endpoint

    Raises:
        HTTPException 403: If user's tenant role is not in allowed_roles
    """

    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    async def __call__(
        self,
        request: Request,
        current_user: Annotated[User, Depends(get_current_user_for_rbac)],
    ) -> User:
        """Check if user has required global role.

        Args:
            request: FastAPI request (contains tenant context from auth middleware)
            current_user: Authenticated user from Clerk JWT

        Returns:
            Authenticated user if authorized

        Raises:
            HTTPException 403: If user lacks required role
        """
        # Get role from request state (set by get_current_user)
        user_role = getattr(request.state, "user_role", None)

        if user_role is None:
            raise HTTPException(
                status_code=403,
                detail="User has no role in this tenant",
            )

        if user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )

        return current_user


class RequireInvestigationRole:
    """Dependency that checks investigation-level permissions.

    Implements AC1, AC2, AC3, AC7:
    - AC1: Global admin bypasses investigation checks
    - AC2: Role-based action restrictions (via allowed_roles)
    - AC3: Returns 404 if user has no access (enumeration prevention)
    - AC7: Integrates with existing Clerk auth

    Args:
        allowed_roles: List of investigation roles that can access
                      (e.g., ["owner", "analyst", "viewer"])

    Raises:
        HTTPException 404: If user has no permission to even see the investigation
        HTTPException 403: If user can see but not perform the action
    """

    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    async def __call__(
        self,
        request: Request,
        investigation_id: Annotated[UUID, Path(...)],
        current_user: Annotated[User, Depends(get_current_user_for_rbac)],
        session: Annotated[AsyncSession, Depends(get_session_for_rbac)],
    ) -> User:
        """Check if user has required investigation permission.

        Args:
            request: FastAPI request (contains tenant context)
            investigation_id: Target investigation from path
            current_user: Authenticated user from Clerk JWT
            session: Database session

        Returns:
            Authenticated user if authorized

        Raises:
            HTTPException 404: User cannot see this investigation exists
            HTTPException 403: User can see but lacks required role
        """
        # Get tenant from request state
        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id is None:
            raise HTTPException(
                status_code=403,
                detail="No tenant context",
            )

        # Check global admin first (AC1, AC5)
        user_role = getattr(request.state, "user_role", None)
        if user_role == UserRole.admin:
            # Admin bypasses all investigation-level checks
            return current_user

        # Check investigation-specific permission
        permission_service = PermissionService(session)
        permission = await permission_service.get_investigation_permission(
            current_user.id, investigation_id
        )

        if permission is None:
            # User has no permission - return 404 to prevent enumeration (AC3)
            raise HTTPException(
                status_code=404,
                detail="Investigation not found",
            )

        if permission.role not in self.allowed_roles:
            # User has permission but not the right role - 403 (AC2)
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions for this action",
            )

        # Store permission in request state for use in route handlers
        request.state.investigation_permission = permission

        return current_user


# Convenience dependencies for common permission patterns
RequireViewer = RequireInvestigationRole(["owner", "analyst", "viewer"])
RequireEditor = RequireInvestigationRole(["owner", "analyst"])
RequireOwner = RequireInvestigationRole(["owner"])

# Type aliases for cleaner route signatures
RequireViewerDep = Annotated[User, Depends(RequireViewer)]
RequireEditorDep = Annotated[User, Depends(RequireEditor)]
RequireOwnerDep = Annotated[User, Depends(RequireOwner)]

# Global admin dependency
RequireAdmin = RequireGlobalRole(["admin"])
RequireAdminDep = Annotated[User, Depends(RequireAdmin)]
