"""Permission checking service for RBAC.

Implements Story 1.4 AC1-3: Permission checking logic for global and
per-investigation access control.

Design notes (per ADR-003):
- Direct DB queries for MVP (< 100 users)
- PermissionCache interface for future Redis swap
- Instant revocation works (no JWT claims)
"""

from enum import StrEnum
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.models.permission import ROLE_HIERARCHY, InvestigationPermission, InvestigationRole
from app.models.user import TenantMembership, UserRole


class PermissionAction(StrEnum):
    """Actions that can be performed on investigations.

    Permission matrix:
    - admin (global): all actions on all investigations in tenant
    - owner: all actions on own investigation
    - analyst: view + edit
    - viewer: view only
    """

    view = "view"
    edit = "edit"
    delete = "delete"
    manage_permissions = "manage_permissions"


# Permission matrix: which roles can perform which actions
# Global admin bypasses this matrix entirely
INVESTIGATION_PERMISSION_MATRIX: dict[str, set[PermissionAction]] = {
    InvestigationRole.owner: {
        PermissionAction.view,
        PermissionAction.edit,
        PermissionAction.delete,
        PermissionAction.manage_permissions,
    },
    InvestigationRole.analyst: {
        PermissionAction.view,
        PermissionAction.edit,
    },
    InvestigationRole.viewer: {
        PermissionAction.view,
    },
}


class PermissionCache(Protocol):
    """Interface for permission caching (for future Redis swap per ADR-003)."""

    async def get_user_permission(
        self, user_id: UUID, investigation_id: UUID
    ) -> InvestigationPermission | None:
        """Get cached permission or None if not cached."""
        ...

    async def set_user_permission(
        self, user_id: UUID, investigation_id: UUID, permission: InvestigationPermission | None
    ) -> None:
        """Cache a permission (or None for "no permission")."""
        ...

    async def invalidate_user_permission(self, user_id: UUID, investigation_id: UUID) -> None:
        """Remove permission from cache."""
        ...

    async def invalidate_investigation(self, investigation_id: UUID) -> None:
        """Remove all permissions for an investigation from cache."""
        ...


class NoOpPermissionCache:
    """No-op cache implementation for MVP (direct DB queries)."""

    async def get_user_permission(
        self,
        user_id: UUID,  # noqa: ARG002
        investigation_id: UUID,  # noqa: ARG002
    ) -> InvestigationPermission | None:
        return None  # Always miss - go to DB

    async def set_user_permission(
        self, user_id: UUID, investigation_id: UUID, permission: InvestigationPermission | None
    ) -> None:
        pass  # No caching

    async def invalidate_user_permission(self, user_id: UUID, investigation_id: UUID) -> None:
        pass  # No cache to invalidate

    async def invalidate_investigation(self, investigation_id: UUID) -> None:
        pass  # No cache to invalidate


class PermissionService:
    """Service for checking and managing investigation permissions.

    Implements AC1: Global admin access to all resources
    Implements AC2: Role-based action restrictions
    Implements AC3: 404 for enumeration prevention
    """

    def __init__(
        self,
        session: AsyncSession,
        cache: PermissionCache | None = None,
    ):
        """Initialize permission service.

        Args:
            session: Database session for queries
            cache: Optional permission cache (defaults to no-op for MVP)
        """
        self.session = session
        self.cache = cache or NoOpPermissionCache()

    async def get_user_tenant_role(self, user_id: UUID, tenant_id: UUID) -> UserRole | None:
        """Get user's global role within a tenant.

        This implements AC5: Global roles checked first.

        Args:
            user_id: User to check
            tenant_id: Tenant context

        Returns:
            UserRole if user has membership, None otherwise
        """
        result = await self.session.execute(
            select(TenantMembership).where(
                TenantMembership.user_id == user_id,
                TenantMembership.tenant_id == tenant_id,
            )
        )
        membership = result.scalar_one_or_none()
        return membership.role if membership else None

    async def is_global_admin(self, user_id: UUID, tenant_id: UUID) -> bool:
        """Check if user is a global admin within the tenant.

        Implements AC1: Global admin overrides all investigation permissions.

        Args:
            user_id: User to check
            tenant_id: Tenant context

        Returns:
            True if user is admin in tenant
        """
        role = await self.get_user_tenant_role(user_id, tenant_id)
        return role == UserRole.admin

    async def get_investigation_permission(
        self, user_id: UUID, investigation_id: UUID
    ) -> InvestigationPermission | None:
        """Get user's permission for a specific investigation.

        Implements AC6: Per-investigation roles from InvestigationPermission table.

        Args:
            user_id: User to check
            investigation_id: Investigation to check access for

        Returns:
            InvestigationPermission if exists, None otherwise
        """
        # Check cache first
        cached = await self.cache.get_user_permission(user_id, investigation_id)
        if cached is not None:
            return cached

        # Query database
        result = await self.session.execute(
            select(InvestigationPermission).where(
                InvestigationPermission.user_id == user_id,
                InvestigationPermission.investigation_id == investigation_id,
            )
        )
        permission = result.scalar_one_or_none()

        # Cache result (including None for "no permission")
        await self.cache.set_user_permission(user_id, investigation_id, permission)

        return permission

    async def get_effective_role(
        self,
        user_id: UUID,
        tenant_id: UUID,
        investigation_id: UUID,
    ) -> tuple[str | None, bool]:
        """Get user's effective role for an investigation.

        Combines global tenant role with investigation-specific permission.
        Global admin overrides investigation roles.

        Args:
            user_id: User to check
            tenant_id: Tenant context
            investigation_id: Target investigation

        Returns:
            Tuple of (effective_role, is_global_admin)
            - effective_role: "admin", "owner", "analyst", "viewer", or None
            - is_global_admin: True if role comes from global admin status
        """
        # Check global admin first (AC1, AC5)
        if await self.is_global_admin(user_id, tenant_id):
            return "admin", True

        # Check investigation-specific permission (AC6)
        permission = await self.get_investigation_permission(user_id, investigation_id)
        if permission:
            return permission.role, False

        return None, False

    def can_perform_action(
        self,
        role: str | None,
        is_global_admin: bool,
        action: PermissionAction,
    ) -> bool:
        """Check if a role can perform an action.

        Implements permission matrix from Dev Notes.

        Args:
            role: User's effective role
            is_global_admin: Whether user is global admin
            action: Action to check

        Returns:
            True if action is allowed
        """
        # Global admin can do anything (AC1)
        if is_global_admin:
            return True

        if role is None:
            return False

        # Check permission matrix
        allowed_actions = INVESTIGATION_PERMISSION_MATRIX.get(role, set())
        return action in allowed_actions

    async def check_investigation_access(
        self,
        user_id: UUID,
        tenant_id: UUID,
        investigation_id: UUID,
        action: PermissionAction,
    ) -> tuple[bool, str | None, bool]:
        """Check if user can perform action on investigation.

        Main entry point for RBAC checks. Returns enough info for proper
        error responses (404 vs 403 per ADR-004).

        Args:
            user_id: User making the request
            tenant_id: Current tenant context
            investigation_id: Target investigation
            action: Requested action

        Returns:
            Tuple of (allowed, role, has_any_access):
            - allowed: True if action is permitted
            - role: User's effective role (or None)
            - has_any_access: True if user can see investigation exists

        The caller should use these values for error responses:
        - not has_any_access -> 404 (enumeration prevention)
        - has_any_access but not allowed -> 403 (permission denied)
        """
        role, is_admin = await self.get_effective_role(user_id, tenant_id, investigation_id)

        has_any_access = role is not None or is_admin
        allowed = self.can_perform_action(role, is_admin, action)

        return allowed, role, has_any_access

    async def list_accessible_investigation_ids(self, user_id: UUID, tenant_id: UUID) -> list[UUID]:
        """Get list of investigation IDs user can access.

        Used for filtering investigation lists and checking if user
        can "see" an investigation exists (for 404 vs 403 decision).

        Args:
            user_id: User to check
            tenant_id: Tenant context

        Returns:
            List of accessible investigation IDs
        """
        # Global admin can see all (need to query investigations table)
        if await self.is_global_admin(user_id, tenant_id):
            # Import here to avoid circular imports
            from app.models.investigation import Investigation  # noqa: PLC0415

            result = await self.session.execute(
                select(Investigation.id).where(Investigation.tenant_id == tenant_id)
            )
            return list(result.scalars().all())

        # Regular users see only investigations they have permissions for
        result = await self.session.execute(
            select(InvestigationPermission.investigation_id).where(
                InvestigationPermission.user_id == user_id
            )
        )
        return list(result.scalars().all())

    def can_grant_role(self, granter_role: str, target_role: str) -> bool:
        """Check if user with granter_role can grant target_role.

        Implements role hierarchy enforcement (AC11).

        Args:
            granter_role: Role of user granting permission
            target_role: Role being granted

        Returns:
            True if grant is allowed by hierarchy
        """
        granter_level = ROLE_HIERARCHY.get(granter_role, 0)
        target_level = ROLE_HIERARCHY.get(target_role, 0)
        return granter_level >= target_level
