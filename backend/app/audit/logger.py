"""Audit logger for authorization events.

Implements Story 1.4 AC8 & AC12: Log all authorization decisions
and security events for compliance and monitoring.

Event types (per Dev Notes):
- permission_granted: User granted access to investigation
- permission_revoked: User access removed from investigation
- permission_denied: User attempted action they lack permission for (403)
- permission_not_found: User attempted access to unknown resource (404)
- self_grant_blocked: User attempted to modify own permission
- cross_tenant_blocked: User attempted cross-tenant permission operation
- role_hierarchy_blocked: User attempted to grant higher role than own
- owner_self_revoke_blocked: Owner tried to revoke own ownership without transfer
"""

import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import ActionType, AuditLog


class PermissionEventType(StrEnum):
    """Types of permission-related audit events."""

    # Standard permission operations
    permission_granted = "permission_granted"
    permission_revoked = "permission_revoked"
    permission_updated = "permission_updated"

    # Access control events
    permission_denied = "permission_denied"  # 403 responses
    permission_not_found = "permission_not_found"  # 404 responses (enumeration)
    access_granted = "access_granted"  # Successful access

    # Security events (blocked operations)
    self_grant_blocked = "self_grant_blocked"
    cross_tenant_blocked = "cross_tenant_blocked"
    role_hierarchy_blocked = "role_hierarchy_blocked"
    owner_self_revoke_blocked = "owner_self_revoke_blocked"


class AuditLogger:
    """Service for logging authorization audit events.

    Provides methods for logging permission operations and security events
    with consistent structure for compliance requirements.
    """

    def __init__(self, session: AsyncSession, tenant_id: UUID):
        """Initialize audit logger.

        Args:
            session: Database session for writing audit logs
            tenant_id: Current tenant context for audit entries
        """
        self.session = session
        self.tenant_id = tenant_id

    async def log_permission_granted(
        self,
        actor_id: UUID,
        target_user_id: UUID,
        investigation_id: UUID,
        role: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Log a permission grant event.

        Args:
            actor_id: User who granted the permission
            target_user_id: User who received the permission
            investigation_id: Investigation the permission is for
            role: Role that was granted
            ip_address: Client IP address
            user_agent: Client user agent
        """
        await self._log_event(
            event_type=PermissionEventType.permission_granted,
            action_type=ActionType.create,
            actor_id=actor_id,
            target_type="investigation_permission",
            target_id=investigation_id,
            details={
                "target_user_id": str(target_user_id),
                "role": role,
                "event_type": PermissionEventType.permission_granted,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def log_permission_updated(
        self,
        actor_id: UUID,
        target_user_id: UUID,
        investigation_id: UUID,
        previous_role: str,
        new_role: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Log a permission update event.

        Args:
            actor_id: User who updated the permission
            target_user_id: User whose permission was updated
            investigation_id: Investigation the permission is for
            previous_role: Role before update
            new_role: Role after update
            ip_address: Client IP address
            user_agent: Client user agent
        """
        await self._log_event(
            event_type=PermissionEventType.permission_updated,
            action_type=ActionType.update,
            actor_id=actor_id,
            target_type="investigation_permission",
            target_id=investigation_id,
            details={
                "target_user_id": str(target_user_id),
                "previous_role": previous_role,
                "new_role": new_role,
                "event_type": PermissionEventType.permission_updated,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def log_permission_revoked(
        self,
        actor_id: UUID,
        target_user_id: UUID,
        investigation_id: UUID,
        previous_role: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Log a permission revocation event.

        Args:
            actor_id: User who revoked the permission
            target_user_id: User whose permission was revoked
            investigation_id: Investigation the permission was for
            previous_role: Role that was revoked
            ip_address: Client IP address
            user_agent: Client user agent
        """
        await self._log_event(
            event_type=PermissionEventType.permission_revoked,
            action_type=ActionType.delete,
            actor_id=actor_id,
            target_type="investigation_permission",
            target_id=investigation_id,
            details={
                "target_user_id": str(target_user_id),
                "previous_role": previous_role,
                "event_type": PermissionEventType.permission_revoked,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def log_permission_denied(
        self,
        actor_id: UUID,
        investigation_id: UUID,
        requested_action: str,
        user_role: str | None = None,
        reason: str = "insufficient_permissions",
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Log a permission denied event (403).

        Args:
            actor_id: User who was denied
            investigation_id: Investigation they tried to access
            requested_action: Action they tried to perform
            user_role: User's actual role
            reason: Why they were denied
            ip_address: Client IP address
            user_agent: Client user agent
        """
        await self._log_event(
            event_type=PermissionEventType.permission_denied,
            action_type=ActionType.read,
            actor_id=actor_id,
            target_type="investigation",
            target_id=investigation_id,
            details={
                "requested_action": requested_action,
                "user_role": user_role,
                "reason": reason,
                "result": "denied",
                "event_type": PermissionEventType.permission_denied,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def log_security_event(
        self,
        event_type: PermissionEventType,
        actor_id: UUID,
        investigation_id: UUID | None = None,
        target_user_id: UUID | None = None,
        requested_role: str | None = None,
        reason: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Log a security-related event (blocked operation).

        Used for:
        - self_grant_blocked
        - cross_tenant_blocked
        - role_hierarchy_blocked
        - owner_self_revoke_blocked

        Args:
            event_type: Type of security event
            actor_id: User who attempted the operation
            investigation_id: Related investigation (if any)
            target_user_id: Target user of the operation (if any)
            requested_role: Role they tried to grant (if applicable)
            reason: Additional context
            ip_address: Client IP address
            user_agent: Client user agent
        """
        details: dict[str, Any] = {
            "event_type": event_type,
            "result": "blocked",
        }
        if target_user_id:
            details["target_user_id"] = str(target_user_id)
        if requested_role:
            details["requested_role"] = requested_role
        if reason:
            details["reason"] = reason

        await self._log_event(
            event_type=event_type,
            action_type=ActionType.update,  # Attempted modification
            actor_id=actor_id,
            target_type="investigation_permission",
            target_id=investigation_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def _log_event(
        self,
        event_type: PermissionEventType,  # noqa: ARG002 - reserved for future use
        action_type: ActionType,
        actor_id: UUID,
        target_type: str,
        target_id: UUID | None,
        details: dict[str, Any],
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Internal method to create audit log entry.

        Creates an AuditLog record with HMAC checksum for tamper detection.
        """
        # Add timestamp to details for context
        details["logged_at"] = datetime.now(UTC).isoformat()

        audit_log = AuditLog(
            tenant_id=self.tenant_id,
            action_type=action_type,
            actor_id=actor_id,
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            checksum="",  # Will be calculated
        )

        # Calculate checksum for integrity
        audit_log.checksum = audit_log.calculate_checksum()

        self.session.add(audit_log)
        # Note: Caller should commit the session


class SimpleAuditLogger:
    """Simple audit logger for anti-abuse and GDPR events.

    Logs to Python logger until full audit database integration.
    Used by webhook handlers and GDPR endpoints.
    """

    def __init__(self) -> None:
        """Initialize simple audit logger."""
        self._logger = logging.getLogger("app.audit.simple")

    async def log_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Log an audit event to Python logger.

        Args:
            event_type: Type of event (e.g., 'signup_blocked_ip_limit')
            details: Event details dict
        """
        self._logger.info(f"Audit event: {event_type} - {details}")
