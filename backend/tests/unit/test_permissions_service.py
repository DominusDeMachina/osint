"""Unit tests for PermissionService.

Tests the permission checking logic for Story 1.4 AC1-3.
"""

from uuid import uuid4

import pytest

from app.models.permission import InvestigationRole
from app.services.permissions import (
    INVESTIGATION_PERMISSION_MATRIX,
    NoOpPermissionCache,
    PermissionAction,
    PermissionService,
)


class TestPermissionAction:
    """Tests for PermissionAction enum."""

    def test_action_values(self) -> None:
        """Verify all expected actions exist."""
        assert PermissionAction.view == "view"
        assert PermissionAction.edit == "edit"
        assert PermissionAction.delete == "delete"
        assert PermissionAction.manage_permissions == "manage_permissions"


class TestPermissionMatrix:
    """Tests for permission matrix constants."""

    def test_owner_has_all_permissions(self) -> None:
        """Owner should have all permissions."""
        owner_perms = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.owner]
        assert PermissionAction.view in owner_perms
        assert PermissionAction.edit in owner_perms
        assert PermissionAction.delete in owner_perms
        assert PermissionAction.manage_permissions in owner_perms

    def test_analyst_can_view_and_edit(self) -> None:
        """Analyst should be able to view and edit."""
        analyst_perms = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.analyst]
        assert PermissionAction.view in analyst_perms
        assert PermissionAction.edit in analyst_perms
        assert PermissionAction.delete not in analyst_perms
        assert PermissionAction.manage_permissions not in analyst_perms

    def test_viewer_can_only_view(self) -> None:
        """Viewer should only be able to view."""
        viewer_perms = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.viewer]
        assert PermissionAction.view in viewer_perms
        assert PermissionAction.edit not in viewer_perms
        assert PermissionAction.delete not in viewer_perms
        assert PermissionAction.manage_permissions not in viewer_perms


class TestNoOpPermissionCache:
    """Tests for NoOpPermissionCache."""

    @pytest.mark.asyncio
    async def test_get_always_returns_none(self) -> None:
        """Cache should always miss (return None)."""
        cache = NoOpPermissionCache()
        result = await cache.get_user_permission(uuid4(), uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_set_is_noop(self) -> None:
        """Set should not raise errors."""
        cache = NoOpPermissionCache()
        # Should not raise
        await cache.set_user_permission(uuid4(), uuid4(), None)

    @pytest.mark.asyncio
    async def test_invalidate_is_noop(self) -> None:
        """Invalidate should not raise errors."""
        cache = NoOpPermissionCache()
        # Should not raise
        await cache.invalidate_user_permission(uuid4(), uuid4())
        await cache.invalidate_investigation(uuid4())


class TestPermissionServiceCanPerformAction:
    """Tests for can_perform_action method (no DB required)."""

    def test_global_admin_can_do_anything(self) -> None:
        """Global admin bypasses permission matrix (AC1)."""
        service = PermissionService(session=None)  # type: ignore

        for action in PermissionAction:
            assert (
                service.can_perform_action(role=None, is_global_admin=True, action=action) is True
            )

    def test_none_role_cannot_do_anything(self) -> None:
        """No role means no permissions."""
        service = PermissionService(session=None)  # type: ignore

        for action in PermissionAction:
            assert (
                service.can_perform_action(role=None, is_global_admin=False, action=action) is False
            )

    def test_owner_can_do_all_actions(self) -> None:
        """Owner has full permissions on investigation."""
        service = PermissionService(session=None)  # type: ignore

        for action in PermissionAction:
            assert (
                service.can_perform_action(role="owner", is_global_admin=False, action=action)
                is True
            )

    def test_analyst_can_view_and_edit(self) -> None:
        """Analyst can view and edit but not delete or manage permissions."""
        service = PermissionService(session=None)  # type: ignore

        assert (
            service.can_perform_action(
                role="analyst", is_global_admin=False, action=PermissionAction.view
            )
            is True
        )
        assert (
            service.can_perform_action(
                role="analyst", is_global_admin=False, action=PermissionAction.edit
            )
            is True
        )
        assert (
            service.can_perform_action(
                role="analyst", is_global_admin=False, action=PermissionAction.delete
            )
            is False
        )
        assert (
            service.can_perform_action(
                role="analyst",
                is_global_admin=False,
                action=PermissionAction.manage_permissions,
            )
            is False
        )

    def test_viewer_can_only_view(self) -> None:
        """Viewer can only view - implements AC2."""
        service = PermissionService(session=None)  # type: ignore

        assert (
            service.can_perform_action(
                role="viewer", is_global_admin=False, action=PermissionAction.view
            )
            is True
        )
        assert (
            service.can_perform_action(
                role="viewer", is_global_admin=False, action=PermissionAction.edit
            )
            is False
        )
        assert (
            service.can_perform_action(
                role="viewer", is_global_admin=False, action=PermissionAction.delete
            )
            is False
        )
        assert (
            service.can_perform_action(
                role="viewer",
                is_global_admin=False,
                action=PermissionAction.manage_permissions,
            )
            is False
        )


class TestPermissionServiceCanGrantRole:
    """Tests for can_grant_role method (role hierarchy enforcement)."""

    def test_owner_can_grant_all_roles(self) -> None:
        """Owner can grant any role including owner."""
        service = PermissionService(session=None)  # type: ignore

        assert service.can_grant_role("owner", "owner") is True
        assert service.can_grant_role("owner", "analyst") is True
        assert service.can_grant_role("owner", "viewer") is True

    def test_analyst_can_grant_analyst_and_viewer(self) -> None:
        """Analyst can grant analyst and viewer but not owner."""
        service = PermissionService(session=None)  # type: ignore

        assert service.can_grant_role("analyst", "owner") is False
        assert service.can_grant_role("analyst", "analyst") is True
        assert service.can_grant_role("analyst", "viewer") is True

    def test_viewer_can_only_grant_viewer(self) -> None:
        """Viewer can only grant viewer role."""
        service = PermissionService(session=None)  # type: ignore

        assert service.can_grant_role("viewer", "owner") is False
        assert service.can_grant_role("viewer", "analyst") is False
        assert service.can_grant_role("viewer", "viewer") is True

    def test_unknown_role_cannot_grant(self) -> None:
        """Unknown role has level 0 and cannot grant anything."""
        service = PermissionService(session=None)  # type: ignore

        assert service.can_grant_role("unknown", "viewer") is False
        assert service.can_grant_role("unknown", "analyst") is False
        assert service.can_grant_role("unknown", "owner") is False
