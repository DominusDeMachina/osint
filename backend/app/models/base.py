"""Base model classes for SQLModel.

Provides base classes for all database models with multi-tenant support:
- TimestampMixin: Automatic created_at/updated_at timestamps
- BaseModel: UUID primary key + timestamps for global tables
- TenantModel: Extends BaseModel with tenant_id for RLS-protected tables
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Return current UTC time as timezone-naive datetime for PostgreSQL TIMESTAMP."""
    return datetime.now(UTC).replace(tzinfo=None)


class TimestampMixin(SQLModel):
    """Mixin for created_at and updated_at timestamps.

    Automatically adds created_at and updated_at fields with server defaults.
    """

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column_kwargs={"server_default": text("CURRENT_TIMESTAMP")},
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column_kwargs={
            "server_default": text("CURRENT_TIMESTAMP"),
            "onupdate": utc_now,
        },
    )

    model_config = {"from_attributes": True}


class BaseModel(TimestampMixin):
    """Base model with UUID primary key and timestamps.

    Use for global tables that are NOT tenant-scoped (e.g., tenants, users).
    """

    id: UUID = Field(default_factory=uuid4, primary_key=True)

    def model_dump_json_safe(self) -> dict[str, Any]:
        """Dump model to JSON-safe dict (UUIDs as strings)."""
        data = self.model_dump()
        for key, value in data.items():
            if isinstance(value, UUID):
                data[key] = str(value)
            elif isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


class TenantModel(BaseModel):
    """Base model for all tenant-scoped tables.

    Extends BaseModel with required tenant_id field for Row-Level Security (RLS).
    All tables using this model will have RLS policies enforcing tenant isolation.

    RLS: Automatically filtered by tenant_id via PostgreSQL RLS policies.
    The tenant_id is set via app.current_tenant session variable.
    """

    tenant_id: UUID = Field(
        ...,  # Required, not nullable
        foreign_key="tenants.id",
        index=True,
        description="Tenant ID for RLS isolation",
    )
