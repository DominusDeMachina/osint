"""AuditLog database model.

Implements NFR-AUD from PRD - Immutable Audit Trail.
Provides tamper-evident logging of all system actions.
"""

import hashlib
import hmac
import json
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field

from app.models.base import TenantModel


def _get_hmac_secret() -> bytes:
    """Get HMAC secret from settings (lazy load to avoid circular imports)."""
    from app.core.config import settings  # noqa: PLC0415

    return settings.audit_hmac_secret.encode()


class ActionType(StrEnum):
    """Type of action being audited.

    Standard CRUD operations plus auth events:
    - create: New resource created
    - read: Resource accessed
    - update: Resource modified
    - delete: Resource deleted
    - export: Data exported
    - login: User logged in
    - logout: User logged out
    """

    create = "create"
    read = "read"
    update = "update"
    delete = "delete"
    export = "export"
    login = "login"
    logout = "logout"


class AuditLog(TenantModel, table=True):
    """Audit log model for immutable action tracking.

    RLS: Automatically filtered by tenant_id via TenantModel.
    All audit entries include HMAC-SHA256 checksums for integrity.

    Attributes:
        action_type: Type of action performed
        actor_id: User ID who performed the action
        target_type: Type of resource affected (e.g., 'investigation')
        target_id: ID of the affected resource
        details: JSONB with additional context
        checksum: HMAC-SHA256 for tamper detection
        ip_address: Client IP address
        user_agent: Client user agent string
    """

    __tablename__ = "audit_logs"

    action_type: ActionType = Field(sa_column=Column(String(50), index=True))
    actor_id: UUID = Field(foreign_key="users.id", index=True)
    target_type: str = Field(max_length=100, index=True)
    target_id: UUID | None = Field(default=None, index=True)
    details: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False, default={}),
    )
    checksum: str = Field(max_length=64)  # SHA-256 hex = 64 chars
    # IPv6 max length is 45 chars (e.g., "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
    ip_address: str | None = Field(default=None, max_length=45)
    user_agent: str | None = Field(default=None, max_length=500)

    def calculate_checksum(self, secret: bytes | None = None) -> str:
        """Calculate HMAC-SHA256 checksum for this audit entry.

        The checksum covers all significant fields to detect tampering.

        Args:
            secret: HMAC secret key (default: from settings.audit_hmac_secret)

        Returns:
            Hex-encoded HMAC-SHA256 digest
        """
        if secret is None:
            secret = _get_hmac_secret()
        # Build canonical representation for checksum
        data = {
            "tenant_id": str(self.tenant_id),
            "action_type": self.action_type.value,
            "actor_id": str(self.actor_id),
            "target_type": self.target_type,
            "target_id": str(self.target_id) if self.target_id else None,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()

    def verify_checksum(self, secret: bytes | None = None) -> bool:
        """Verify the stored checksum matches calculated value.

        Args:
            secret: HMAC secret key (default: from settings.audit_hmac_secret)

        Returns:
            True if checksum is valid, False if tampered
        """
        if secret is None:
            secret = _get_hmac_secret()
        return hmac.compare_digest(self.checksum, self.calculate_checksum(secret))
