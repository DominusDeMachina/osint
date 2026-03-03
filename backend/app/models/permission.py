"""Investigation permission database model.

Implements per-investigation RBAC as defined in Story 1.4.
InvestigationPermission stores fine-grained access control for each investigation.

This is separate from TenantMembership (global tenant roles) to support:
- Per-investigation access control (owner, analyst, viewer per investigation)
- Independent audit trails for permission changes
- Different lifecycles for global vs investigation-level access
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Column, String, UniqueConstraint
from sqlmodel import Field, Relationship

from app.models.base import TimestampMixin


if TYPE_CHECKING:
    from app.models.investigation import Investigation
    from app.models.user import User


class InvestigationRole(StrEnum):
    """Role within a specific investigation.

    Defines the level of access a user has within an investigation:
    - owner: Full control including permission management and deletion
    - analyst: Can view and edit investigation content
    - viewer: Read-only access to investigation
    """

    owner = "owner"
    analyst = "analyst"
    viewer = "viewer"


# Role hierarchy for permission enforcement
# Higher value = more privileges
ROLE_HIERARCHY: dict[str, int] = {
    "owner": 3,
    "analyst": 2,
    "viewer": 1,
}


class InvestigationPermission(TimestampMixin, table=True):
    """Per-investigation permission assignment.

    Global table - NOT tenant-scoped. References tenant-scoped investigations
    but exists outside RLS to support permission queries across tenants.

    This implements AC6: Per-investigation roles stored in InvestigationPermission
    table with user_id, investigation_id, role.

    Attributes:
        id: Unique permission identifier
        user_id: User receiving the permission
        investigation_id: Investigation being granted access to
        role: User's role within this investigation
        granted_by: User who granted this permission
        granted_at: Timestamp when permission was granted
    """

    __tablename__ = "investigation_permissions"
    __table_args__ = (
        UniqueConstraint("user_id", "investigation_id", name="uq_user_investigation_permission"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="users.id", index=True)
    investigation_id: UUID = Field(foreign_key="investigations.id", index=True)
    role: InvestigationRole = Field(sa_column=Column(String(50), index=True, nullable=False))
    granted_by: UUID = Field(foreign_key="users.id")
    granted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Relationships
    user: "User" = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[InvestigationPermission.user_id]"}
    )
    granter: "User" = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[InvestigationPermission.granted_by]"}
    )
    investigation: "Investigation" = Relationship(back_populates="permissions")
