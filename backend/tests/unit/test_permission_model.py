"""Unit tests for InvestigationPermission model.

Tests the permission model created in Story 1.4 Task 1.
"""

from datetime import UTC, datetime
from uuid import uuid4

from app.models.permission import (
    ROLE_HIERARCHY,
    InvestigationPermission,
    InvestigationRole,
)


class TestInvestigationRole:
    """Tests for InvestigationRole enum."""

    def test_role_values(self) -> None:
        """Verify all expected roles exist."""
        assert InvestigationRole.owner == "owner"
        assert InvestigationRole.analyst == "analyst"
        assert InvestigationRole.viewer == "viewer"

    def test_role_is_string_enum(self) -> None:
        """Role should be usable as string."""
        role = InvestigationRole.owner
        assert role == "owner"
        assert str(role) == "owner"


class TestRoleHierarchy:
    """Tests for role hierarchy constants."""

    def test_hierarchy_levels(self) -> None:
        """Verify role hierarchy is correctly defined."""
        assert ROLE_HIERARCHY["owner"] == 3
        assert ROLE_HIERARCHY["analyst"] == 2
        assert ROLE_HIERARCHY["viewer"] == 1

    def test_owner_higher_than_analyst(self) -> None:
        """Owner should have higher privilege than analyst."""
        assert ROLE_HIERARCHY["owner"] > ROLE_HIERARCHY["analyst"]

    def test_analyst_higher_than_viewer(self) -> None:
        """Analyst should have higher privilege than viewer."""
        assert ROLE_HIERARCHY["analyst"] > ROLE_HIERARCHY["viewer"]

    def test_hierarchy_can_determine_grant_permission(self) -> None:
        """Role hierarchy can be used to check if user can grant a role."""

        def can_grant(granter_role: str, target_role: str) -> bool:
            return ROLE_HIERARCHY.get(granter_role, 0) >= ROLE_HIERARCHY.get(target_role, 0)

        # Owner can grant all roles
        assert can_grant("owner", "owner") is True
        assert can_grant("owner", "analyst") is True
        assert can_grant("owner", "viewer") is True

        # Analyst can grant analyst and viewer
        assert can_grant("analyst", "owner") is False
        assert can_grant("analyst", "analyst") is True
        assert can_grant("analyst", "viewer") is True

        # Viewer cannot grant any role
        assert can_grant("viewer", "owner") is False
        assert can_grant("viewer", "analyst") is False
        assert can_grant("viewer", "viewer") is True


class TestInvestigationPermissionModel:
    """Tests for InvestigationPermission model."""

    def test_create_permission_with_all_fields(self) -> None:
        """Permission can be created with all required fields."""
        user_id = uuid4()
        investigation_id = uuid4()
        granter_id = uuid4()
        now = datetime.utcnow()

        permission = InvestigationPermission(
            user_id=user_id,
            investigation_id=investigation_id,
            role=InvestigationRole.analyst,
            granted_by=granter_id,
            granted_at=now,
        )

        assert permission.user_id == user_id
        assert permission.investigation_id == investigation_id
        assert permission.role == InvestigationRole.analyst
        assert permission.granted_by == granter_id
        assert permission.granted_at == now

    def test_permission_has_uuid_id(self) -> None:
        """Permission should auto-generate UUID id."""
        permission = InvestigationPermission(
            user_id=uuid4(),
            investigation_id=uuid4(),
            role=InvestigationRole.viewer,
            granted_by=uuid4(),
        )

        assert permission.id is not None

    def test_permission_role_types(self) -> None:
        """All role types can be assigned to permission."""
        base_kwargs = {
            "user_id": uuid4(),
            "investigation_id": uuid4(),
            "granted_by": uuid4(),
        }

        for role in InvestigationRole:
            permission = InvestigationPermission(**base_kwargs, role=role)
            assert permission.role == role

    def test_tablename_is_correct(self) -> None:
        """Verify table name follows naming convention."""
        assert InvestigationPermission.__tablename__ == "investigation_permissions"

    def test_permission_has_timestamps(self) -> None:
        """Permission should have created_at and updated_at from TimestampMixin."""
        permission = InvestigationPermission(
            user_id=uuid4(),
            investigation_id=uuid4(),
            role=InvestigationRole.owner,
            granted_by=uuid4(),
        )

        # TimestampMixin provides these defaults
        assert hasattr(permission, "created_at")
        assert hasattr(permission, "updated_at")

    def test_permission_granted_at_default(self) -> None:
        """granted_at should default to current time."""
        before = datetime.now(UTC)

        permission = InvestigationPermission(
            user_id=uuid4(),
            investigation_id=uuid4(),
            role=InvestigationRole.analyst,
            granted_by=uuid4(),
        )

        after = datetime.now(UTC)

        assert permission.granted_at is not None
        assert before <= permission.granted_at <= after
