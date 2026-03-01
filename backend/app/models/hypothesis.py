"""Hypothesis and EvidenceItem database models.

Implements FR-HYP from PRD - Hypothesis Lifecycle Management.
Hypotheses are investigative theories with supporting evidence.
"""

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Column, String
from sqlmodel import Field, Relationship

from app.models.base import TenantModel


if TYPE_CHECKING:
    from app.models.investigation import Investigation


class HypothesisStatus(StrEnum):
    """Status of a hypothesis in its lifecycle.

    - proposed: Initial hypothesis creation
    - under_investigation: Actively being investigated
    - confirmed: Hypothesis confirmed with evidence
    - refuted: Hypothesis disproven
    """

    proposed = "proposed"
    under_investigation = "under_investigation"
    confirmed = "confirmed"
    refuted = "refuted"


class Hypothesis(TenantModel, table=True):
    """Hypothesis model for investigative theories.

    RLS: Automatically filtered by tenant_id via TenantModel.
    Hypotheses belong to an investigation and have evidence chains.

    Attributes:
        investigation_id: Foreign key to investigations table
        description: Detailed description of the hypothesis
        confidence: Confidence score 0.0-1.0
        status: Current status in hypothesis lifecycle
        created_by: User ID who created the hypothesis
    """

    __tablename__ = "hypotheses"

    investigation_id: UUID = Field(foreign_key="investigations.id", index=True)
    description: str = Field(max_length=5000)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: HypothesisStatus = Field(
        default=HypothesisStatus.proposed,
        sa_column=Column(String(50), index=True, default=HypothesisStatus.proposed),
    )
    created_by: UUID | None = Field(default=None, foreign_key="users.id")

    # Relationships
    investigation: "Investigation" = Relationship(back_populates="hypotheses")
    evidence_items: list["EvidenceItem"] = Relationship(back_populates="hypothesis")


class EvidenceItem(TenantModel, table=True):
    """Evidence item model for supporting hypotheses.

    RLS: Automatically filtered by tenant_id via TenantModel.
    Evidence items are linked to hypotheses and form evidence chains.

    Attributes:
        hypothesis_id: Foreign key to hypotheses table
        content: Description of the evidence
        source_url: URL to the evidence source
        weight: How strongly this evidence supports/refutes hypothesis
        added_by: User ID who added the evidence
    """

    __tablename__ = "evidence_items"

    hypothesis_id: UUID = Field(foreign_key="hypotheses.id", index=True)
    content: str = Field(max_length=5000)
    source_url: str | None = Field(default=None, max_length=2000)
    weight: float = Field(default=1.0, ge=-1.0, le=1.0)  # Negative = refutes
    added_by: UUID | None = Field(default=None, foreign_key="users.id")

    # Relationships
    hypothesis: "Hypothesis" = Relationship(back_populates="evidence_items")
