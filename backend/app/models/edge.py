"""EntityEdge database model.

Implements FR-REL from PRD - Relationship Management.
Edges represent relationships between entities in the graph.
"""

from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship

from app.models.base import TenantModel


if TYPE_CHECKING:
    from app.models.entity import Entity


class EdgeType(StrEnum):
    """Type of relationship between entities.

    Relationship types from PRD:
    - owns: Ownership relationship
    - works_at: Employment relationship
    - related_to: Generic relationship
    - controls: Control/directorship
    - registered_at: Domain registration
    """

    owns = "owns"
    works_at = "works_at"
    related_to = "related_to"
    controls = "controls"
    registered_at = "registered_at"


class EntityEdge(TenantModel, table=True):
    """Edge model for entity relationships.

    RLS: Automatically filtered by tenant_id via TenantModel.
    Represents directed relationships between two entities.

    Attributes:
        source_id: Foreign key to source entity
        target_id: Foreign key to target entity
        edge_type: Type of relationship
        confidence: Confidence score 0.0-1.0
        properties: JSONB field for edge-specific attributes
        source_url: Evidence source URL
    """

    __tablename__ = "entity_edges"

    source_id: UUID = Field(foreign_key="entities.id", index=True)
    target_id: UUID = Field(foreign_key="entities.id", index=True)
    edge_type: EdgeType = Field(index=True)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    properties: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, default={}),
    )
    source_url: str | None = Field(default=None, max_length=2000)

    # Relationships
    source_entity: "Entity" = Relationship(
        back_populates="outgoing_edges",
        sa_relationship_kwargs={"foreign_keys": "[EntityEdge.source_id]"},
    )
    target_entity: "Entity" = Relationship(
        back_populates="incoming_edges",
        sa_relationship_kwargs={"foreign_keys": "[EntityEdge.target_id]"},
    )
