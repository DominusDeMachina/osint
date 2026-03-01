"""Unit tests for base SQLModel classes."""

from datetime import datetime
from uuid import UUID

from app.models.base import BaseModel, TenantModel, TimestampMixin


class TestTimestampMixin:
    """Tests for TimestampMixin."""

    def test_timestamp_fields_exist(self) -> None:
        """Verify TimestampMixin has created_at and updated_at fields."""
        assert "created_at" in TimestampMixin.model_fields
        assert "updated_at" in TimestampMixin.model_fields

    def test_timestamp_types(self) -> None:
        """Verify timestamp fields are datetime type."""
        created_field = TimestampMixin.model_fields["created_at"]
        updated_field = TimestampMixin.model_fields["updated_at"]
        assert created_field.annotation == datetime
        assert updated_field.annotation == datetime


class TestBaseModel:
    """Tests for BaseModel."""

    def test_base_model_has_id_field(self) -> None:
        """Verify BaseModel has UUID id field."""
        assert "id" in BaseModel.model_fields
        id_field = BaseModel.model_fields["id"]
        assert id_field.annotation == UUID

    def test_base_model_inherits_timestamps(self) -> None:
        """Verify BaseModel has timestamp fields from mixin."""
        assert "created_at" in BaseModel.model_fields
        assert "updated_at" in BaseModel.model_fields

    def test_model_config_from_attributes(self) -> None:
        """Verify model_config has from_attributes=True for Pydantic compatibility."""
        assert hasattr(BaseModel, "model_config")
        assert BaseModel.model_config.get("from_attributes") is True


class TestTenantModel:
    """Tests for TenantModel."""

    def test_tenant_model_has_tenant_id(self) -> None:
        """Verify TenantModel has tenant_id field (AC5)."""
        assert "tenant_id" in TenantModel.model_fields

    def test_tenant_id_is_uuid(self) -> None:
        """Verify tenant_id is UUID type."""
        tenant_field = TenantModel.model_fields["tenant_id"]
        assert tenant_field.annotation == UUID

    def test_tenant_id_is_required(self) -> None:
        """Verify tenant_id is required (not nullable)."""
        tenant_field = TenantModel.model_fields["tenant_id"]
        assert tenant_field.is_required() is True

    def test_tenant_model_inherits_timestamps(self) -> None:
        """Verify TenantModel has timestamp fields (AC5)."""
        assert "created_at" in TenantModel.model_fields
        assert "updated_at" in TenantModel.model_fields

    def test_tenant_model_has_id(self) -> None:
        """Verify TenantModel has UUID id field."""
        assert "id" in TenantModel.model_fields
