"""Tenant database model.

Implements multi-tenant organization management.
Tenants are the top-level organizational unit for data isolation.
"""

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlmodel import Field, Relationship

from app.models.base import TimestampMixin


if TYPE_CHECKING:
    from app.models.user import TenantMembership


class Tenant(TimestampMixin, table=True):
    """Tenant organization model.

    Global table - NOT tenant-scoped. Each tenant represents
    an organization that has its own isolated data via RLS.

    Attributes:
        id: Unique tenant identifier
        name: Display name of the tenant/organization
        slug: URL-friendly unique identifier (optional)
        is_active: Whether the tenant is active
    """

    __tablename__ = "tenants"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(max_length=255, index=True)
    slug: str | None = Field(default=None, max_length=100, unique=True, index=True)
    is_active: bool = Field(default=True)

    # Relationships
    memberships: list["TenantMembership"] = Relationship(back_populates="tenant")
