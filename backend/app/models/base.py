"""Base model classes for SQLModel."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlmodel import Field, SQLModel


class TimestampMixin(SQLModel):
    """Mixin for created_at and updated_at timestamps."""

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class BaseModel(TimestampMixin):
    """Base model with UUID primary key and timestamps."""

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
