"""Pydantic schemas for Investigation endpoints.

Defines request/response models for investigation CRUD operations.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.investigation import InvestigationStatus


class InvestigationBase(BaseModel):
    """Base investigation fields."""

    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=5000)


class InvestigationCreate(InvestigationBase):
    """Schema for creating an investigation."""

    pass


class InvestigationUpdate(BaseModel):
    """Schema for updating an investigation.

    All fields optional to support partial updates.
    """

    title: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=5000)
    status: InvestigationStatus | None = None


class InvestigationResponse(InvestigationBase):
    """Schema for investigation response."""

    id: UUID
    status: InvestigationStatus
    owner_id: UUID
    tenant_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class InvestigationListResponse(BaseModel):
    """Schema for list of investigations response."""

    data: list[InvestigationResponse]
    total: int
