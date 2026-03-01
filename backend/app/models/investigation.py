"""Investigation database model.

Implements FR-INV from PRD - Investigation Management.
Investigations are the core organizational unit for OSINT research.
"""

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlmodel import Field, Relationship

from app.models.base import TenantModel


if TYPE_CHECKING:
    from app.models.entity import InvestigationEntity
    from app.models.hypothesis import Hypothesis


class InvestigationStatus(StrEnum):
    """Status of an investigation.

    - active: Investigation is currently being worked on
    - paused: Investigation is temporarily paused
    - closed: Investigation is completed/closed
    """

    active = "active"
    paused = "paused"
    closed = "closed"


class Investigation(TenantModel, table=True):
    """Investigation model for OSINT research.

    RLS: Automatically filtered by tenant_id via TenantModel.
    Each investigation belongs to exactly one tenant and contains
    entities, hypotheses, and evidence.

    Attributes:
        title: Display title of the investigation
        description: Detailed description of investigation goals
        status: Current status (active, paused, closed)
        owner_id: User ID of the investigation owner
    """

    __tablename__ = "investigations"

    title: str = Field(max_length=255, index=True)
    description: str | None = Field(default=None, max_length=5000)
    status: InvestigationStatus = Field(default=InvestigationStatus.active, index=True)
    owner_id: UUID = Field(foreign_key="users.id", index=True)

    # Relationships
    investigation_entities: list["InvestigationEntity"] = Relationship(
        back_populates="investigation"
    )
    hypotheses: list["Hypothesis"] = Relationship(back_populates="investigation")
