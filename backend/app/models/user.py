"""User and TenantMembership database models.

Implements user management with Clerk integration and tenant membership.
Users can belong to multiple tenants with different roles.
"""

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Column, String, UniqueConstraint
from sqlmodel import Field, Relationship

from app.models.base import TimestampMixin


if TYPE_CHECKING:
    from app.models.tenant import Tenant


class UserRole(StrEnum):
    """User role within a tenant.

    Defines the level of access a user has within a tenant:
    - admin: Full administrative access
    - analyst: Can create/edit investigations and entities
    - viewer: Read-only access to investigations
    """

    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(TimestampMixin, table=True):
    """User model linked to Clerk authentication.

    Global table - NOT tenant-scoped. Users can be members
    of multiple tenants via TenantMembership.

    Attributes:
        id: Unique user identifier
        clerk_id: External ID from Clerk authentication
        email: User's email address
        name: User's display name
        avatar_url: URL to user's avatar image
        is_active: Whether the user account is active
    """

    __tablename__ = "users"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    clerk_id: str = Field(unique=True, index=True, max_length=255)
    email: str = Field(unique=True, index=True, max_length=255)
    name: str | None = Field(default=None, max_length=255)
    avatar_url: str | None = Field(default=None, max_length=500)
    is_active: bool = Field(default=True)

    # Relationships
    memberships: list["TenantMembership"] = Relationship(back_populates="user")


class TenantMembership(TimestampMixin, table=True):
    """Junction table for user-tenant membership with role.

    Global table - NOT tenant-scoped. Defines which users
    belong to which tenants and their roles.

    Attributes:
        id: Unique membership identifier
        user_id: Foreign key to users table
        tenant_id: Foreign key to tenants table
        role: User's role within this tenant
    """

    __tablename__ = "tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant"),)

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="users.id", index=True)
    tenant_id: UUID = Field(foreign_key="tenants.id", index=True)
    role: UserRole = Field(
        default=UserRole.viewer,
        sa_column=Column(String(50), default=UserRole.viewer),
    )

    # Relationships
    user: "User" = Relationship(back_populates="memberships")
    tenant: "Tenant" = Relationship(back_populates="memberships")
