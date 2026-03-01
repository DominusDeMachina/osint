"""Pydantic schemas for auth endpoints."""

from uuid import UUID

from pydantic import BaseModel, EmailStr


class TenantInfo(BaseModel):
    """Tenant information in user response."""

    id: UUID
    name: str


class UserResponse(BaseModel):
    """Response schema for current user endpoint."""

    id: UUID
    clerk_id: str
    email: EmailStr
    name: str | None
    avatar_url: str | None
    is_active: bool
    tenant: TenantInfo | None
    role: str | None

    class Config:
        from_attributes = True
