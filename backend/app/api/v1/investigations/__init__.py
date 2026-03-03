"""Investigations API module."""

from app.api.v1.investigations.permissions import router as permissions_router
from app.api.v1.investigations.routes import router


__all__ = ["permissions_router", "router"]
