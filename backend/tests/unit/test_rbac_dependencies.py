"""Unit tests for RBAC dependencies.

Tests the FastAPI dependencies created in Story 1.4 Task 3.
These are unit tests that test the core logic without requiring database.
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

# Import RBAC components directly to avoid circular import issues
from app.core.security.rbac import (
    RequireEditor,
    RequireGlobalRole,
    RequireInvestigationRole,
    RequireOwner,
    RequireViewer,
)
from app.models.permission import InvestigationPermission, InvestigationRole
from app.models.user import User, UserRole


class TestRequireGlobalRole:
    """Tests for RequireGlobalRole dependency."""

    @pytest.mark.asyncio
    async def test_admin_passes_admin_check(self) -> None:
        """Admin role should pass admin requirement."""
        dependency = RequireGlobalRole(["admin"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        request = MagicMock()
        request.state.user_role = UserRole.admin

        result = await dependency(request=request, current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_analyst_fails_admin_check(self) -> None:
        """Analyst role should fail admin requirement."""
        dependency = RequireGlobalRole(["admin"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        request = MagicMock()
        request.state.user_role = UserRole.analyst

        with pytest.raises(HTTPException) as exc_info:
            await dependency(request=request, current_user=user)
        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_no_role_fails(self) -> None:
        """No role should fail any requirement."""
        dependency = RequireGlobalRole(["admin", "analyst", "viewer"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        request = MagicMock()
        request.state.user_role = None

        with pytest.raises(HTTPException) as exc_info:
            await dependency(request=request, current_user=user)
        assert exc_info.value.status_code == 403
        assert "no role" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_multiple_allowed_roles(self) -> None:
        """Multiple roles can be allowed."""
        dependency = RequireGlobalRole(["admin", "analyst"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        request = MagicMock()

        # Admin should pass
        request.state.user_role = UserRole.admin
        result = await dependency(request=request, current_user=user)
        assert result == user

        # Analyst should pass
        request.state.user_role = UserRole.analyst
        result = await dependency(request=request, current_user=user)
        assert result == user

        # Viewer should fail
        request.state.user_role = UserRole.viewer
        with pytest.raises(HTTPException) as exc_info:
            await dependency(request=request, current_user=user)
        assert exc_info.value.status_code == 403


class TestRequireInvestigationRole:
    """Tests for RequireInvestigationRole dependency."""

    def _create_mock_request(
        self,
        tenant_id: str | None = None,
        user_role: UserRole | None = UserRole.viewer,
    ) -> MagicMock:
        """Helper to create mock request with state."""
        request = MagicMock()
        request.state.tenant_id = tenant_id or uuid4()
        request.state.user_role = user_role
        return request

    def _create_mock_session(self, permission: InvestigationPermission | None = None) -> AsyncMock:
        """Helper to create mock session with permission query."""
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = permission
        session.execute.return_value = mock_result
        return session

    @pytest.mark.asyncio
    async def test_global_admin_bypasses_check(self) -> None:
        """Global admin should bypass investigation permission check (AC1)."""
        dependency = RequireInvestigationRole(["owner"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        investigation_id = uuid4()
        request = self._create_mock_request(user_role=UserRole.admin)
        session = self._create_mock_session(permission=None)

        result = await dependency(
            request=request,
            investigation_id=investigation_id,
            current_user=user,
            session=session,
        )
        assert result == user
        # Session should not be called - admin bypasses
        session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_tenant_context_returns_403(self) -> None:
        """Missing tenant context should return 403."""
        dependency = RequireInvestigationRole(["viewer"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        investigation_id = uuid4()
        request = MagicMock()
        request.state.tenant_id = None
        request.state.user_role = UserRole.viewer
        session = self._create_mock_session()

        with pytest.raises(HTTPException) as exc_info:
            await dependency(
                request=request,
                investigation_id=investigation_id,
                current_user=user,
                session=session,
            )
        assert exc_info.value.status_code == 403
        assert "tenant" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_no_permission_returns_404(self) -> None:
        """No permission should return 404 (AC3 - enumeration prevention)."""
        dependency = RequireInvestigationRole(["viewer"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        investigation_id = uuid4()
        request = self._create_mock_request()
        session = self._create_mock_session(permission=None)

        with pytest.raises(HTTPException) as exc_info:
            await dependency(
                request=request,
                investigation_id=investigation_id,
                current_user=user,
                session=session,
            )
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_wrong_role_returns_403(self) -> None:
        """Having permission but wrong role should return 403 (AC2)."""
        dependency = RequireInvestigationRole(["owner"])  # Require owner
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        investigation_id = uuid4()
        request = self._create_mock_request()

        # User has viewer role
        permission = InvestigationPermission(
            id=uuid4(),
            user_id=user.id,
            investigation_id=investigation_id,
            role=InvestigationRole.viewer,
            granted_by=uuid4(),
        )
        session = self._create_mock_session(permission=permission)

        with pytest.raises(HTTPException) as exc_info:
            await dependency(
                request=request,
                investigation_id=investigation_id,
                current_user=user,
                session=session,
            )
        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_correct_role_passes(self) -> None:
        """Correct role should pass and return user."""
        dependency = RequireInvestigationRole(["owner", "analyst"])
        user = User(id=uuid4(), clerk_id="user_test", email="test@test.com")
        investigation_id = uuid4()
        request = self._create_mock_request()

        # User has analyst role
        permission = InvestigationPermission(
            id=uuid4(),
            user_id=user.id,
            investigation_id=investigation_id,
            role=InvestigationRole.analyst,
            granted_by=uuid4(),
        )
        session = self._create_mock_session(permission=permission)

        result = await dependency(
            request=request,
            investigation_id=investigation_id,
            current_user=user,
            session=session,
        )
        assert result == user
        # Permission should be stored in request state
        assert request.state.investigation_permission == permission


class TestConvenienceDependencies:
    """Tests for convenience dependency instances."""

    def test_require_viewer_allows_all_roles(self) -> None:
        """RequireViewer should allow owner, analyst, viewer."""
        assert "owner" in RequireViewer.allowed_roles
        assert "analyst" in RequireViewer.allowed_roles
        assert "viewer" in RequireViewer.allowed_roles

    def test_require_editor_allows_owner_and_analyst(self) -> None:
        """RequireEditor should allow owner and analyst."""
        assert "owner" in RequireEditor.allowed_roles
        assert "analyst" in RequireEditor.allowed_roles
        assert "viewer" not in RequireEditor.allowed_roles

    def test_require_owner_allows_only_owner(self) -> None:
        """RequireOwner should allow only owner."""
        assert "owner" in RequireOwner.allowed_roles
        assert "analyst" not in RequireOwner.allowed_roles
        assert "viewer" not in RequireOwner.allowed_roles
