"""Permission management endpoints for investigations.

Implements Story 1.4 Task 5 & AC4: Investigation owner can assign roles
(owner, analyst, viewer) to other users on their investigations.

Also implements:
- AC9: Self-grant prevention
- AC10: Cross-tenant validation
- AC11: Role hierarchy enforcement
- AC15: Owner cannot revoke own ownership without transfer
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path, Request
from pydantic import BaseModel
from sqlmodel import select

from app.api.deps import CurrentUserDep, TenantSessionDep
from app.audit.logger import AuditLogger, PermissionEventType
from app.models.permission import ROLE_HIERARCHY, InvestigationPermission, InvestigationRole
from app.models.user import TenantMembership, User, UserRole
from app.services.permissions import PermissionService


router = APIRouter(tags=["permissions"])


class PermissionGrantRequest(BaseModel):
    """Schema for granting a permission."""

    user_id: UUID
    role: InvestigationRole


class PermissionUpdateRequest(BaseModel):
    """Schema for updating a permission."""

    role: InvestigationRole


class PermissionResponse(BaseModel):
    """Schema for permission response."""

    id: UUID
    user_id: UUID
    investigation_id: UUID
    role: InvestigationRole
    granted_by: UUID
    granted_at: datetime
    # Include user info for display
    user_email: str | None = None
    user_name: str | None = None

    model_config = {"from_attributes": True}


class PermissionListResponse(BaseModel):
    """Schema for list of permissions response."""

    data: list[PermissionResponse]


async def check_owner_permission(
    request: Request,
    investigation_id: UUID,
    current_user: User,
    session,
) -> InvestigationPermission | None:
    """Check if current user has owner permission on investigation.

    Returns the permission if user is owner or admin, raises 404/403 otherwise.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    user_role = getattr(request.state, "user_role", None)

    # Admin bypasses permission checks
    if user_role == UserRole.admin:
        return None  # No specific permission, but allowed

    # Check investigation-specific permission
    permission_service = PermissionService(session)
    permission = await permission_service.get_investigation_permission(
        current_user.id, investigation_id
    )

    if permission is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if permission.role != InvestigationRole.owner:
        raise HTTPException(
            status_code=403, detail="Only investigation owner can manage permissions"
        )

    return permission


@router.get(
    "/investigations/{investigation_id}/permissions",
    response_model=PermissionListResponse,
)
async def list_permissions(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> PermissionListResponse:
    """List all permissions for an investigation.

    Only the investigation owner (or admin) can view permissions.

    Args:
        investigation_id: Investigation UUID

    Returns:
        List of permissions with user info
    """
    await check_owner_permission(request, investigation_id, current_user, session)

    # Fetch permissions with user info
    result = await session.execute(
        select(InvestigationPermission, User)
        .join(User, InvestigationPermission.user_id == User.id)  # type: ignore[arg-type]
        .where(InvestigationPermission.investigation_id == investigation_id)
    )
    rows = result.all()

    permissions = []
    for perm, user in rows:
        perm_dict = {
            "id": perm.id,
            "user_id": perm.user_id,
            "investigation_id": perm.investigation_id,
            "role": perm.role,
            "granted_by": perm.granted_by,
            "granted_at": perm.granted_at,
            "user_email": user.email,
            "user_name": user.name,
        }
        permissions.append(PermissionResponse(**perm_dict))

    return PermissionListResponse(data=permissions)


@router.post(
    "/investigations/{investigation_id}/permissions",
    response_model=PermissionResponse,
    status_code=201,
)
async def grant_permission(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    data: PermissionGrantRequest,
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> PermissionResponse:
    """Grant permission to a user on an investigation.

    Only the investigation owner (or admin) can grant permissions.

    Implements:
    - AC4: Owner can assign roles
    - AC9: Self-grant prevention
    - AC10: Cross-tenant validation
    - AC11: Role hierarchy enforcement

    Args:
        investigation_id: Investigation UUID
        data: User ID and role to grant

    Returns:
        Created permission

    Raises:
        HTTPException 403: Self-grant, hierarchy violation, or not owner
        HTTPException 404: Target user not found or cross-tenant
    """
    granter_permission = await check_owner_permission(
        request, investigation_id, current_user, session
    )

    tenant_id: UUID | None = getattr(request.state, "tenant_id", None)
    user_role = getattr(request.state, "user_role", None)
    is_admin = user_role == UserRole.admin

    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    # Initialize audit logger
    audit_logger = AuditLogger(session, tenant_id)
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")

    # AC9: Self-grant prevention (admin can modify self)
    if data.user_id == current_user.id and not is_admin:
        await audit_logger.log_security_event(
            event_type=PermissionEventType.self_grant_blocked,
            actor_id=current_user.id,
            investigation_id=investigation_id,
            target_user_id=data.user_id,
            requested_role=data.role,
            reason="self_grant_attempt",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await session.commit()
        raise HTTPException(status_code=403, detail="Cannot modify your own permissions")

    # AC10: Cross-tenant validation - check target user is in same tenant
    membership_result = await session.execute(
        select(TenantMembership).where(
            TenantMembership.user_id == data.user_id,
            TenantMembership.tenant_id == tenant_id,
        )
    )
    target_membership = membership_result.scalar_one_or_none()
    if target_membership is None:
        await audit_logger.log_security_event(
            event_type=PermissionEventType.cross_tenant_blocked,
            actor_id=current_user.id,
            investigation_id=investigation_id,
            target_user_id=data.user_id,
            requested_role=data.role,
            reason="target_user_not_in_tenant",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await session.commit()
        # Return 404 to prevent tenant enumeration
        raise HTTPException(status_code=404, detail="User not found")

    # AC11: Role hierarchy enforcement (admin bypasses)
    if not is_admin and granter_permission:
        granter_level = ROLE_HIERARCHY.get(granter_permission.role, 0)
        target_level = ROLE_HIERARCHY.get(data.role, 0)
        if granter_level < target_level:
            await audit_logger.log_security_event(
                event_type=PermissionEventType.role_hierarchy_blocked,
                actor_id=current_user.id,
                investigation_id=investigation_id,
                target_user_id=data.user_id,
                requested_role=data.role,
                reason=f"granter_role={granter_permission.role}",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await session.commit()
            raise HTTPException(status_code=403, detail="Cannot grant role higher than your own")

    # Check if permission already exists
    existing_result = await session.execute(
        select(InvestigationPermission).where(
            InvestigationPermission.user_id == data.user_id,
            InvestigationPermission.investigation_id == investigation_id,
        )
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        # Update existing permission
        previous_role = existing.role
        existing.role = data.role
        existing.granted_by = current_user.id
        existing.granted_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(existing)
        permission = existing

        # Log permission updated (not granted) for existing permissions
        await audit_logger.log_permission_updated(
            actor_id=current_user.id,
            target_user_id=data.user_id,
            investigation_id=investigation_id,
            previous_role=previous_role,
            new_role=data.role,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    else:
        # Create new permission
        permission = InvestigationPermission(
            user_id=data.user_id,
            investigation_id=investigation_id,
            role=data.role,
            granted_by=current_user.id,
        )
        session.add(permission)
        await session.commit()
        await session.refresh(permission)

        # Log permission granted for new permissions
        await audit_logger.log_permission_granted(
            actor_id=current_user.id,
            target_user_id=data.user_id,
            investigation_id=investigation_id,
            role=data.role,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    await session.commit()

    # Get user info for response
    user_result = await session.execute(select(User).where(User.id == data.user_id))
    user = user_result.scalar_one()

    return PermissionResponse(
        id=permission.id,
        user_id=permission.user_id,
        investigation_id=permission.investigation_id,
        role=permission.role,
        granted_by=permission.granted_by,
        granted_at=permission.granted_at,
        user_email=user.email,
        user_name=user.name,
    )


@router.patch(
    "/investigations/{investigation_id}/permissions/{user_id}",
    response_model=PermissionResponse,
)
async def update_permission(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    user_id: Annotated[UUID, Path(...)],
    data: PermissionUpdateRequest,
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> PermissionResponse:
    """Update a user's permission on an investigation.

    Only the investigation owner (or admin) can update permissions.

    Args:
        investigation_id: Investigation UUID
        user_id: User whose permission to update
        data: New role

    Returns:
        Updated permission
    """
    granter_permission = await check_owner_permission(
        request, investigation_id, current_user, session
    )

    user_role = getattr(request.state, "user_role", None)
    is_admin = user_role == UserRole.admin

    # AC9: Self-grant prevention
    if user_id == current_user.id and not is_admin:
        raise HTTPException(status_code=403, detail="Cannot modify your own permissions")

    # AC11: Role hierarchy enforcement
    if not is_admin and granter_permission:
        granter_level = ROLE_HIERARCHY.get(granter_permission.role, 0)
        target_level = ROLE_HIERARCHY.get(data.role, 0)
        if granter_level < target_level:
            raise HTTPException(status_code=403, detail="Cannot grant role higher than your own")

    # Fetch existing permission
    result = await session.execute(
        select(InvestigationPermission).where(
            InvestigationPermission.user_id == user_id,
            InvestigationPermission.investigation_id == investigation_id,
        )
    )
    permission = result.scalar_one_or_none()

    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Update
    permission.role = data.role
    permission.granted_by = current_user.id
    permission.granted_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(permission)

    # Get user info
    user_result = await session.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one()

    return PermissionResponse(
        id=permission.id,
        user_id=permission.user_id,
        investigation_id=permission.investigation_id,
        role=permission.role,
        granted_by=permission.granted_by,
        granted_at=permission.granted_at,
        user_email=user.email,
        user_name=user.name,
    )


@router.delete(
    "/investigations/{investigation_id}/permissions/{user_id}",
    status_code=204,
)
async def revoke_permission(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    user_id: Annotated[UUID, Path(...)],
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> None:
    """Revoke a user's permission on an investigation.

    Only the investigation owner (or admin) can revoke permissions.

    Implements:
    - AC9: Self-revoke prevention (for non-owners)
    - AC15: Owner cannot revoke own ownership without another owner

    Args:
        investigation_id: Investigation UUID
        user_id: User whose permission to revoke
    """
    await check_owner_permission(request, investigation_id, current_user, session)

    user_role = getattr(request.state, "user_role", None)
    is_admin = user_role == UserRole.admin

    # Fetch target permission
    result = await session.execute(
        select(InvestigationPermission).where(
            InvestigationPermission.user_id == user_id,
            InvestigationPermission.investigation_id == investigation_id,
        )
    )
    permission = result.scalar_one_or_none()

    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")

    tenant_id: UUID | None = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    audit_logger = AuditLogger(session, tenant_id)
    ip_address = request.client.host if request.client else None
    user_agent_header = request.headers.get("User-Agent")

    # AC15: Owner self-revoke prevention
    if user_id == current_user.id:
        if permission.role == InvestigationRole.owner:
            # Check if there are other owners
            owners_result = await session.execute(
                select(InvestigationPermission).where(
                    InvestigationPermission.investigation_id == investigation_id,
                    InvestigationPermission.role == InvestigationRole.owner,
                    InvestigationPermission.user_id != current_user.id,
                )
            )
            other_owners = owners_result.scalars().all()
            if len(other_owners) == 0 and not is_admin:
                await audit_logger.log_security_event(
                    event_type=PermissionEventType.owner_self_revoke_blocked,
                    actor_id=current_user.id,
                    investigation_id=investigation_id,
                    target_user_id=user_id,
                    reason="no_other_owners",
                    ip_address=ip_address,
                    user_agent=user_agent_header,
                )
                await session.commit()
                raise HTTPException(
                    status_code=403,
                    detail="Transfer ownership to another user before leaving",
                )
        elif not is_admin:
            # AC9: Non-owner cannot self-revoke
            await audit_logger.log_security_event(
                event_type=PermissionEventType.self_grant_blocked,
                actor_id=current_user.id,
                investigation_id=investigation_id,
                target_user_id=user_id,
                reason="self_revoke_attempt",
                ip_address=ip_address,
                user_agent=user_agent_header,
            )
            await session.commit()
            raise HTTPException(status_code=403, detail="Cannot revoke your own permissions")

    # Log permission revoked
    await audit_logger.log_permission_revoked(
        actor_id=current_user.id,
        target_user_id=user_id,
        investigation_id=investigation_id,
        previous_role=permission.role,
        ip_address=ip_address,
        user_agent=user_agent_header,
    )

    await session.delete(permission)
    await session.commit()
