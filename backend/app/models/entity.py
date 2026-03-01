"""Entity database model.

Implements FR-ENT from PRD - Entity Management.
Entities are the core data objects in OSINT investigations.
"""

from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship

from app.models.base import TenantModel


if TYPE_CHECKING:
    from app.models.edge import EntityEdge
    from app.models.investigation import Investigation


class EntityType(StrEnum):
    """Type of entity in the investigation.

    Entity types with their UI colors (from PRD):
    - person: Purple
    - organization: Cyan
    - domain: Amber
    - email: Pink
    - phone: Emerald
    - address: Indigo
    """

    person = "person"
    organization = "organization"
    domain = "domain"
    email = "email"
    phone = "phone"
    address = "address"


class Entity(TenantModel, table=True):
    """Entity model for OSINT data objects.

    RLS: Automatically filtered by tenant_id via TenantModel.
    Entities represent people, organizations, domains, etc.
    that are being investigated.

    Attributes:
        entity_type: Type of entity (person, organization, etc.)
        name: Display name or identifier
        properties: JSONB field for type-specific attributes
        confidence: Confidence score 0.0-1.0 for entity validity
        source_url: Original data source URL
    """

    __tablename__ = "entities"

    entity_type: EntityType = Field(index=True)
    name: str = Field(max_length=500, index=True)
    properties: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, default={}),
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_url: str | None = Field(default=None, max_length=2000)

    # Relationships
    investigation_entities: list["InvestigationEntity"] = Relationship(back_populates="entity")
    outgoing_edges: list["EntityEdge"] = Relationship(
        back_populates="source_entity",
        sa_relationship_kwargs={"foreign_keys": "[EntityEdge.source_id]"},
    )
    incoming_edges: list["EntityEdge"] = Relationship(
        back_populates="target_entity",
        sa_relationship_kwargs={"foreign_keys": "[EntityEdge.target_id]"},
    )


class InvestigationEntity(TenantModel, table=True):
    """Junction table linking investigations to entities.

    RLS: Automatically filtered by tenant_id via TenantModel.
    Entities can belong to multiple investigations within the same tenant.

    Attributes:
        investigation_id: Foreign key to investigations table
        entity_id: Foreign key to entities table
        added_by: User ID who added this entity to the investigation
    """

    __tablename__ = "investigation_entities"

    investigation_id: UUID = Field(foreign_key="investigations.id", index=True)
    entity_id: UUID = Field(foreign_key="entities.id", index=True)
    added_by: UUID | None = Field(default=None, foreign_key="users.id")

    # Relationships
    investigation: "Investigation" = Relationship(back_populates="investigation_entities")
    entity: "Entity" = Relationship(back_populates="investigation_entities")
