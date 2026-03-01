"""Unit tests for Tenant and User models."""

from app.models.tenant import Tenant
from app.models.user import TenantMembership, User, UserRole


class TestTenantModel:
    """Tests for Tenant model."""

    def test_tenant_is_table(self) -> None:
        """Verify Tenant is a database table."""
        assert hasattr(Tenant, "__tablename__")
        assert Tenant.__tablename__ == "tenants"

    def test_tenant_has_required_fields(self) -> None:
        """Verify Tenant has id and name fields."""
        assert "id" in Tenant.model_fields
        assert "name" in Tenant.model_fields

    def test_tenant_has_timestamps(self) -> None:
        """Verify Tenant has timestamp fields."""
        assert "created_at" in Tenant.model_fields
        assert "updated_at" in Tenant.model_fields

    def test_tenant_not_tenant_scoped(self) -> None:
        """Verify Tenant does NOT have tenant_id (global table)."""
        assert "tenant_id" not in Tenant.model_fields


class TestUserModel:
    """Tests for User model."""

    def test_user_is_table(self) -> None:
        """Verify User is a database table."""
        assert hasattr(User, "__tablename__")
        assert User.__tablename__ == "users"

    def test_user_has_clerk_id(self) -> None:
        """Verify User has clerk_id for Clerk integration."""
        assert "clerk_id" in User.model_fields

    def test_user_has_email(self) -> None:
        """Verify User has email field."""
        assert "email" in User.model_fields

    def test_user_has_name(self) -> None:
        """Verify User has name field."""
        assert "name" in User.model_fields

    def test_user_not_tenant_scoped(self) -> None:
        """Verify User does NOT have tenant_id (global table)."""
        assert "tenant_id" not in User.model_fields


class TestUserRole:
    """Tests for UserRole enum."""

    def test_role_values(self) -> None:
        """Verify UserRole has expected values."""
        assert UserRole.admin == "admin"
        assert UserRole.analyst == "analyst"
        assert UserRole.viewer == "viewer"


class TestTenantMembership:
    """Tests for TenantMembership junction table."""

    def test_membership_is_table(self) -> None:
        """Verify TenantMembership is a database table."""
        assert hasattr(TenantMembership, "__tablename__")
        assert TenantMembership.__tablename__ == "tenant_memberships"

    def test_membership_has_user_id(self) -> None:
        """Verify TenantMembership has user_id."""
        assert "user_id" in TenantMembership.model_fields

    def test_membership_has_tenant_id(self) -> None:
        """Verify TenantMembership has tenant_id."""
        assert "tenant_id" in TenantMembership.model_fields

    def test_membership_has_role(self) -> None:
        """Verify TenantMembership has role field."""
        assert "role" in TenantMembership.model_fields
