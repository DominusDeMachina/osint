"""Integration tests for investigation permissions.

Tests Story 1.4 AC4, AC6, AC7, AC8:
- AC4: Investigation owner can assign roles to other users
- AC6: Per-investigation roles stored in InvestigationPermission table
- AC7: RBAC integrates with existing Clerk auth
- AC8: Permission changes are audited
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.investigations.permissions import (
    PermissionGrantRequest,
    grant_permission,
)
from app.audit.logger import AuditLogger, PermissionEventType
from app.models.permission import InvestigationPermission, InvestigationRole
from app.models.user import TenantMembership, User, UserRole
from app.services.permissions import PermissionService


class TestPermissionGrantFlow:
    """Test full permission grant/revoke flow (AC4)."""

    @pytest.mark.asyncio
    async def test_owner_can_grant_analyst_permission(self) -> None:
        """Owner should be able to grant analyst role to another user."""
        owner_id = uuid4()
        target_user_id = uuid4()
        investigation_id = uuid4()
        tenant_id = uuid4()

        owner = User(id=owner_id, clerk_id="owner_clerk", email="owner@test.com")
        target_user = User(id=target_user_id, clerk_id="target_clerk", email="target@test.com")

        owner_permission = InvestigationPermission(
            id=uuid4(),
            user_id=owner_id,
            investigation_id=investigation_id,
            role=InvestigationRole.owner,
            granted_by=owner_id,
            granted_at=datetime.now(UTC),
        )

        target_membership = TenantMembership(
            id=uuid4(),
            user_id=target_user_id,
            tenant_id=tenant_id,
            role=UserRole.viewer,
        )

        # Mock request
        request = MagicMock()
        request.state.tenant_id = tenant_id
        request.state.user_role = UserRole.viewer  # Not admin
        request.client.host = "127.0.0.1"
        request.headers.get.return_value = "TestAgent"

        # Mock session
        session = AsyncMock()

        # Mock permission check - return owner permission
        permission_result = MagicMock()
        permission_result.scalar_one_or_none.return_value = owner_permission

        # Mock membership check - return target's membership
        membership_result = MagicMock()
        membership_result.scalar_one_or_none.return_value = target_membership

        # Mock existing permission check - none exists
        existing_result = MagicMock()
        existing_result.scalar_one_or_none.return_value = None

        # Mock user query for response
        user_result = MagicMock()
        user_result.scalar_one.return_value = target_user

        # Set up session.execute to return different results
        session.execute.side_effect = [
            permission_result,  # check_owner_permission
            membership_result,  # cross-tenant check
            existing_result,  # existing permission check
            user_result,  # get user for response
        ]

        data = PermissionGrantRequest(user_id=target_user_id, role=InvestigationRole.analyst)

        result = await grant_permission(
            request=request,
            investigation_id=investigation_id,
            data=data,
            current_user=owner,
            session=session,
        )

        assert result.user_id == target_user_id
        assert result.role == InvestigationRole.analyst
        assert result.investigation_id == investigation_id

    @pytest.mark.asyncio
    async def test_self_grant_blocked_returns_403(self) -> None:
        """User cannot grant permission to themselves (AC9)."""
        user_id = uuid4()
        investigation_id = uuid4()
        tenant_id = uuid4()

        user = User(id=user_id, clerk_id="user_clerk", email="user@test.com")

        owner_permission = InvestigationPermission(
            id=uuid4(),
            user_id=user_id,
            investigation_id=investigation_id,
            role=InvestigationRole.owner,
            granted_by=user_id,
            granted_at=datetime.now(UTC),
        )

        request = MagicMock()
        request.state.tenant_id = tenant_id
        request.state.user_role = UserRole.viewer  # Not admin
        request.client.host = "127.0.0.1"
        request.headers.get.return_value = "TestAgent"

        session = AsyncMock()
        permission_result = MagicMock()
        permission_result.scalar_one_or_none.return_value = owner_permission
        session.execute.return_value = permission_result

        data = PermissionGrantRequest(
            user_id=user_id,  # Same as current user - self grant!
            role=InvestigationRole.analyst,
        )

        with pytest.raises(HTTPException) as exc_info:
            await grant_permission(
                request=request,
                investigation_id=investigation_id,
                data=data,
                current_user=user,
                session=session,
            )

        assert exc_info.value.status_code == 403
        assert "own permissions" in exc_info.value.detail.lower()


class TestInvestigationListFiltering:
    """Test investigation listing filters by permission (AC6)."""

    @pytest.mark.asyncio
    async def test_user_only_sees_permitted_investigations(self) -> None:
        """User should only see investigations they have permissions for."""
        user_id = uuid4()
        tenant_id = uuid4()
        investigation_1 = uuid4()  # User has permission
        investigation_2 = uuid4()  # User does NOT have permission

        session = AsyncMock()

        # Mock the permission query result
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [investigation_1]  # Only inv 1
        mock_result.scalars.return_value = mock_scalars
        session.execute.return_value = mock_result

        service = PermissionService(session)

        # Mock is_global_admin to return False
        with patch.object(service, "is_global_admin", return_value=False):
            accessible_ids = await service.list_accessible_investigation_ids(user_id, tenant_id)

        assert investigation_1 in accessible_ids
        assert investigation_2 not in accessible_ids


class TestPermissionAuditLogging:
    """Test permission changes are audited (AC8)."""

    @pytest.mark.asyncio
    async def test_permission_grant_is_logged(self) -> None:
        """Permission grant should create audit log entry."""
        tenant_id = uuid4()
        actor_id = uuid4()
        target_user_id = uuid4()
        investigation_id = uuid4()

        session = AsyncMock()

        logger = AuditLogger(session, tenant_id)

        await logger.log_permission_granted(
            actor_id=actor_id,
            target_user_id=target_user_id,
            investigation_id=investigation_id,
            role="analyst",
            ip_address="127.0.0.1",
            user_agent="TestAgent",
        )

        # Verify session.add was called with an AuditLog
        session.add.assert_called_once()
        audit_log = session.add.call_args[0][0]
        assert audit_log.tenant_id == tenant_id
        assert audit_log.actor_id == actor_id
        assert "analyst" in str(audit_log.details)

    @pytest.mark.asyncio
    async def test_permission_revoke_is_logged(self) -> None:
        """Permission revocation should create audit log entry."""
        tenant_id = uuid4()
        actor_id = uuid4()
        target_user_id = uuid4()
        investigation_id = uuid4()

        session = AsyncMock()

        logger = AuditLogger(session, tenant_id)

        await logger.log_permission_revoked(
            actor_id=actor_id,
            target_user_id=target_user_id,
            investigation_id=investigation_id,
            previous_role="analyst",
            ip_address="127.0.0.1",
            user_agent="TestAgent",
        )

        session.add.assert_called_once()
        audit_log = session.add.call_args[0][0]
        assert "analyst" in str(audit_log.details)

    @pytest.mark.asyncio
    async def test_security_event_logged_on_blocked_operation(self) -> None:
        """Security events should be logged when operations are blocked."""
        tenant_id = uuid4()
        actor_id = uuid4()
        investigation_id = uuid4()

        session = AsyncMock()

        logger = AuditLogger(session, tenant_id)

        await logger.log_security_event(
            event_type=PermissionEventType.self_grant_blocked,
            actor_id=actor_id,
            investigation_id=investigation_id,
            reason="self_grant_attempt",
            ip_address="127.0.0.1",
            user_agent="TestAgent",
        )

        session.add.assert_called_once()
        audit_log = session.add.call_args[0][0]
        assert "blocked" in str(audit_log.details)


class TestCrossTenantValidation:
    """Test cross-tenant permission operations are blocked (AC10)."""

    @pytest.mark.asyncio
    async def test_cross_tenant_grant_returns_404(self) -> None:
        """Granting permission to user in different tenant returns 404."""
        owner_id = uuid4()
        target_user_id = uuid4()
        investigation_id = uuid4()
        tenant_a = uuid4()

        owner = User(id=owner_id, clerk_id="owner_clerk", email="owner@test.com")

        owner_permission = InvestigationPermission(
            id=uuid4(),
            user_id=owner_id,
            investigation_id=investigation_id,
            role=InvestigationRole.owner,
            granted_by=owner_id,
            granted_at=datetime.now(UTC),
        )

        request = MagicMock()
        request.state.tenant_id = tenant_a
        request.state.user_role = UserRole.viewer
        request.client.host = "127.0.0.1"
        request.headers.get.return_value = "TestAgent"

        session = AsyncMock()

        # Owner permission check succeeds
        permission_result = MagicMock()
        permission_result.scalar_one_or_none.return_value = owner_permission

        # Membership check fails - target not in tenant
        membership_result = MagicMock()
        membership_result.scalar_one_or_none.return_value = None  # Not found!

        session.execute.side_effect = [permission_result, membership_result]

        data = PermissionGrantRequest(user_id=target_user_id, role=InvestigationRole.analyst)

        with pytest.raises(HTTPException) as exc_info:
            await grant_permission(
                request=request,
                investigation_id=investigation_id,
                data=data,
                current_user=owner,
                session=session,
            )

        # Should be 404, not 403, to prevent tenant enumeration
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail.lower()


class TestRoleHierarchyEnforcement:
    """Test role hierarchy is enforced (AC11)."""

    @pytest.mark.asyncio
    async def test_analyst_cannot_manage_permissions(self) -> None:
        """Analyst should not be able to manage permissions at all."""
        analyst_id = uuid4()
        target_user_id = uuid4()
        investigation_id = uuid4()
        tenant_id = uuid4()

        analyst = User(id=analyst_id, clerk_id="analyst_clerk", email="analyst@test.com")

        # Analyst permission (not owner)
        analyst_permission = InvestigationPermission(
            id=uuid4(),
            user_id=analyst_id,
            investigation_id=investigation_id,
            role=InvestigationRole.analyst,  # Not owner!
            granted_by=uuid4(),
            granted_at=datetime.now(UTC),
        )

        request = MagicMock()
        request.state.tenant_id = tenant_id
        request.state.user_role = UserRole.analyst
        request.client.host = "127.0.0.1"
        request.headers.get.return_value = "TestAgent"

        session = AsyncMock()

        permission_result = MagicMock()
        permission_result.scalar_one_or_none.return_value = analyst_permission
        session.execute.return_value = permission_result

        data = PermissionGrantRequest(
            user_id=target_user_id,
            role=InvestigationRole.viewer,
        )

        with pytest.raises(HTTPException) as exc_info:
            await grant_permission(
                request=request,
                investigation_id=investigation_id,
                data=data,
                current_user=analyst,
                session=session,
            )

        # Analyst can't manage permissions - only owner can
        assert exc_info.value.status_code == 403
