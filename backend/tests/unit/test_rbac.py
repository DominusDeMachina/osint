"""Comprehensive RBAC unit tests.

Tests Story 1.4 acceptance criteria:
- AC1: Global admin overrides investigation permissions
- AC2: Viewer cannot edit
- AC3: No-permission returns 404 (not 403)
- AC5: Global roles checked first
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.security.rbac import (
    RequireInvestigationRole,
)
from app.models.permission import InvestigationPermission, InvestigationRole
from app.models.user import User, UserRole
from app.services.permissions import (
    INVESTIGATION_PERMISSION_MATRIX,
    PermissionAction,
    PermissionService,
)


class TestGlobalAdminOverride:
    """AC1: Global admin overrides investigation permissions."""

    @pytest.mark.asyncio
    async def test_admin_bypasses_investigation_permission_check(self) -> None:
        """Admin should not need investigation-level permission."""
        dependency = RequireInvestigationRole(["owner"])
        user = User(id=uuid4(), clerk_id="user_admin", email="admin@test.com")
        investigation_id = uuid4()

        request = MagicMock()
        request.state.tenant_id = uuid4()
        request.state.user_role = UserRole.admin  # Global admin

        session = AsyncMock()
        # Session should NOT be called - admin bypasses DB check
        session.execute.return_value = MagicMock()

        result = await dependency(
            request=request,
            investigation_id=investigation_id,
            current_user=user,
            session=session,
        )

        assert result == user
        session.execute.assert_not_called()

    def test_admin_can_perform_all_actions_via_service(self) -> None:
        """Admin can perform any action according to service logic."""
        service = PermissionService(session=None)  # type: ignore

        for action in PermissionAction:
            result = service.can_perform_action(
                role=None,  # No investigation role
                is_global_admin=True,  # But is admin
                action=action,
            )
            assert result is True, f"Admin should be able to {action}"


class TestViewerCannotEdit:
    """AC2: Viewer cannot edit."""

    @pytest.mark.asyncio
    async def test_viewer_denied_edit_action(self) -> None:
        """Viewer with permission should get 403 on edit endpoints."""
        dependency = RequireInvestigationRole(["owner", "analyst"])  # Edit requires these
        user = User(id=uuid4(), clerk_id="user_viewer", email="viewer@test.com")
        investigation_id = uuid4()

        request = MagicMock()
        request.state.tenant_id = uuid4()
        request.state.user_role = UserRole.viewer

        # Create viewer permission
        permission = InvestigationPermission(
            id=uuid4(),
            user_id=user.id,
            investigation_id=investigation_id,
            role=InvestigationRole.viewer,
            granted_by=uuid4(),
        )

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = permission
        session.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await dependency(
                request=request,
                investigation_id=investigation_id,
                current_user=user,
                session=session,
            )

        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in exc_info.value.detail

    def test_viewer_cannot_edit_via_permission_matrix(self) -> None:
        """Viewer role should not include edit action in permission matrix."""
        viewer_actions = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.viewer]
        assert PermissionAction.edit not in viewer_actions
        assert PermissionAction.delete not in viewer_actions
        assert PermissionAction.manage_permissions not in viewer_actions

    def test_viewer_can_only_view_via_service(self) -> None:
        """Viewer should only be able to view, not edit."""
        service = PermissionService(session=None)  # type: ignore

        # Viewer can view
        assert (
            service.can_perform_action(
                role="viewer", is_global_admin=False, action=PermissionAction.view
            )
            is True
        )

        # Viewer cannot edit
        assert (
            service.can_perform_action(
                role="viewer", is_global_admin=False, action=PermissionAction.edit
            )
            is False
        )


class TestNoPermissionReturns404:
    """AC3: No-permission returns 404 (not 403) for enumeration prevention."""

    @pytest.mark.asyncio
    async def test_no_permission_returns_404(self) -> None:
        """User with no permission should get 404, not 403."""
        dependency = RequireInvestigationRole(["viewer"])
        user = User(id=uuid4(), clerk_id="user_no_perm", email="noperm@test.com")
        investigation_id = uuid4()

        request = MagicMock()
        request.state.tenant_id = uuid4()
        request.state.user_role = UserRole.viewer  # Not admin

        # No permission exists
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # No permission
        session.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await dependency(
                request=request,
                investigation_id=investigation_id,
                current_user=user,
                session=session,
            )

        # Should be 404, not 403
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_wrong_role_returns_403_not_404(self) -> None:
        """User with wrong role should get 403 (they know it exists)."""
        dependency = RequireInvestigationRole(["owner"])  # Require owner
        user = User(id=uuid4(), clerk_id="user_analyst", email="analyst@test.com")
        investigation_id = uuid4()

        request = MagicMock()
        request.state.tenant_id = uuid4()
        request.state.user_role = UserRole.analyst

        # User has analyst permission (not owner)
        permission = InvestigationPermission(
            id=uuid4(),
            user_id=user.id,
            investigation_id=investigation_id,
            role=InvestigationRole.analyst,
            granted_by=uuid4(),
        )

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = permission
        session.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await dependency(
                request=request,
                investigation_id=investigation_id,
                current_user=user,
                session=session,
            )

        # Should be 403 (they have some access, just not enough)
        assert exc_info.value.status_code == 403


class TestGlobalRolesPrecedence:
    """AC5: Global roles (tenant roles) are checked first."""

    @pytest.mark.asyncio
    async def test_global_admin_checked_before_investigation_permission(self) -> None:
        """Admin check should happen before DB query for investigation permission."""
        dependency = RequireInvestigationRole(["owner"])
        user = User(id=uuid4(), clerk_id="user_admin", email="admin@test.com")
        investigation_id = uuid4()

        request = MagicMock()
        request.state.tenant_id = uuid4()
        request.state.user_role = UserRole.admin

        session = AsyncMock()

        await dependency(
            request=request,
            investigation_id=investigation_id,
            current_user=user,
            session=session,
        )

        # DB should not be called at all for admin
        session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_admin_requires_db_permission_check(self) -> None:
        """Non-admin users must have DB permission checked."""
        dependency = RequireInvestigationRole(["viewer"])
        user = User(id=uuid4(), clerk_id="user_member", email="member@test.com")
        investigation_id = uuid4()

        request = MagicMock()
        request.state.tenant_id = uuid4()
        request.state.user_role = UserRole.viewer  # Not admin

        permission = InvestigationPermission(
            id=uuid4(),
            user_id=user.id,
            investigation_id=investigation_id,
            role=InvestigationRole.viewer,
            granted_by=uuid4(),
        )

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = permission
        session.execute.return_value = mock_result

        await dependency(
            request=request,
            investigation_id=investigation_id,
            current_user=user,
            session=session,
        )

        # DB should be called for non-admin
        session.execute.assert_called_once()


class TestPermissionHierarchy:
    """Test permission hierarchy (owner > analyst > viewer)."""

    def test_owner_has_all_permissions(self) -> None:
        """Owner should have all permissions."""
        owner_perms = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.owner]
        assert PermissionAction.view in owner_perms
        assert PermissionAction.edit in owner_perms
        assert PermissionAction.delete in owner_perms
        assert PermissionAction.manage_permissions in owner_perms

    def test_analyst_has_view_and_edit(self) -> None:
        """Analyst should have view and edit."""
        analyst_perms = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.analyst]
        assert PermissionAction.view in analyst_perms
        assert PermissionAction.edit in analyst_perms
        assert PermissionAction.delete not in analyst_perms
        assert PermissionAction.manage_permissions not in analyst_perms

    def test_viewer_has_view_only(self) -> None:
        """Viewer should have view only."""
        viewer_perms = INVESTIGATION_PERMISSION_MATRIX[InvestigationRole.viewer]
        assert PermissionAction.view in viewer_perms
        assert len(viewer_perms) == 1  # Only view
