"""Investigation API routes with RBAC.

Implements Story 1.4 Task 4: Investigation endpoints with RBAC checks.

Endpoints:
- GET /investigations - List user's accessible investigations
- GET /investigations/{id} - Get investigation (requires view permission)
- POST /investigations - Create investigation (user becomes owner)
- PATCH /investigations/{id} - Update investigation (requires edit permission)
- DELETE /investigations/{id} - Delete investigation (requires owner role)
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path, Request
from sqlmodel import select

from app.api.deps import CurrentUserDep, TenantSessionDep
from app.api.v1.investigations.schemas import (
    InvestigationCreate,
    InvestigationListResponse,
    InvestigationResponse,
    InvestigationUpdate,
)
from app.audit.logger import AuditLogger, PermissionEventType
from app.models.investigation import Investigation, InvestigationStatus
from app.models.permission import InvestigationPermission, InvestigationRole
from app.models.user import UserRole
from app.services.permissions import PermissionService


router = APIRouter(prefix="/investigations", tags=["investigations"])


def _get_request_metadata(request: Request) -> tuple[str | None, str | None]:
    """Extract IP address and user agent from request for audit logging."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")
    return ip_address, user_agent


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    request: Request,
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> InvestigationListResponse:
    """List investigations accessible to the current user.

    Implements AC1: Admin sees all investigations in tenant.
    Regular users only see investigations they have permissions for.

    Returns:
        List of accessible investigations
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    user_role = getattr(request.state, "user_role", None)

    # Admin sees all investigations in tenant (AC1)
    if user_role == UserRole.admin:
        result = await session.execute(
            select(Investigation).where(Investigation.tenant_id == tenant_id)
        )
        investigations = list(result.scalars().all())
    else:
        # Get permission service to find accessible investigation IDs
        permission_service = PermissionService(session)
        accessible_ids = await permission_service.list_accessible_investigation_ids(
            current_user.id, tenant_id
        )

        if not accessible_ids:
            return InvestigationListResponse(data=[], total=0)

        result = await session.execute(
            select(Investigation).where(
                Investigation.id.in_(accessible_ids),  # type: ignore[attr-defined]
                Investigation.tenant_id == tenant_id,
            )
        )
        investigations = list(result.scalars().all())

    return InvestigationListResponse(
        data=[InvestigationResponse.model_validate(inv) for inv in investigations],
        total=len(investigations),
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> InvestigationResponse:
    """Get a specific investigation.

    Implements AC2, AC3: Returns 404 if user has no access (enumeration prevention),
    otherwise returns the investigation.

    Args:
        investigation_id: Investigation UUID from path

    Returns:
        Investigation details

    Raises:
        HTTPException 404: Investigation not found or no access
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    user_role = getattr(request.state, "user_role", None)

    # Admin can access any investigation (AC1)
    if user_role == UserRole.admin:
        result = await session.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.tenant_id == tenant_id,
            )
        )
        investigation = result.scalar_one_or_none()
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return InvestigationResponse.model_validate(investigation)

    # Check permission for non-admin users
    permission_service = PermissionService(session)
    permission = await permission_service.get_investigation_permission(
        current_user.id, investigation_id
    )

    if permission is None:
        # Log permission not found event (AC8, AC12)
        audit_logger = AuditLogger(session, tenant_id)
        ip_address, user_agent = _get_request_metadata(request)
        await audit_logger.log_security_event(
            event_type=PermissionEventType.permission_not_found,
            actor_id=current_user.id,
            investigation_id=investigation_id,
            reason="no_permission_for_investigation",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await session.commit()
        # Return 404 to prevent enumeration (AC3)
        raise HTTPException(status_code=404, detail="Investigation not found")

    # User has permission - fetch the investigation
    result = await session.execute(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.tenant_id == tenant_id,
        )
    )
    investigation = result.scalar_one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return InvestigationResponse.model_validate(investigation)


@router.post("", response_model=InvestigationResponse, status_code=201)
async def create_investigation(
    request: Request,
    data: InvestigationCreate,
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> InvestigationResponse:
    """Create a new investigation.

    The creating user automatically becomes the owner with full permissions.

    Args:
        data: Investigation creation data

    Returns:
        Created investigation
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    # Create investigation with current user as owner
    investigation = Investigation(
        title=data.title,
        description=data.description,
        status=InvestigationStatus.active,
        owner_id=current_user.id,
        tenant_id=tenant_id,
    )
    session.add(investigation)

    # Grant owner permission to creator
    permission = InvestigationPermission(
        user_id=current_user.id,
        investigation_id=investigation.id,
        role=InvestigationRole.owner,
        granted_by=current_user.id,
    )
    session.add(permission)

    await session.commit()
    await session.refresh(investigation)

    return InvestigationResponse.model_validate(investigation)


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    data: InvestigationUpdate,
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> InvestigationResponse:
    """Update an investigation.

    Requires edit permission (owner or analyst role).

    Implements AC2: Viewer cannot edit - returns 403.

    Args:
        investigation_id: Investigation UUID from path
        data: Fields to update

    Returns:
        Updated investigation

    Raises:
        HTTPException 404: Investigation not found or no access
        HTTPException 403: User has view but not edit permission
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    user_role = getattr(request.state, "user_role", None)

    # Check permission
    if user_role != UserRole.admin:
        permission_service = PermissionService(session)
        permission = await permission_service.get_investigation_permission(
            current_user.id, investigation_id
        )

        if permission is None:
            # Log permission not found (AC8, AC12)
            audit_logger = AuditLogger(session, tenant_id)
            ip_address, user_agent = _get_request_metadata(request)
            await audit_logger.log_security_event(
                event_type=PermissionEventType.permission_not_found,
                actor_id=current_user.id,
                investigation_id=investigation_id,
                reason="no_permission_for_investigation",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await session.commit()
            raise HTTPException(status_code=404, detail="Investigation not found")

        if permission.role not in [InvestigationRole.owner, InvestigationRole.analyst]:
            # Log permission denied (AC8, AC12)
            audit_logger = AuditLogger(session, tenant_id)
            ip_address, user_agent = _get_request_metadata(request)
            await audit_logger.log_permission_denied(
                actor_id=current_user.id,
                investigation_id=investigation_id,
                requested_action="edit",
                user_role=permission.role,
                reason="viewer_cannot_edit",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await session.commit()
            raise HTTPException(status_code=403, detail="Insufficient permissions to edit")

    # Fetch and update investigation
    result = await session.execute(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.tenant_id == tenant_id,
        )
    )
    investigation = result.scalar_one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Apply updates
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(investigation, field, value)

    await session.commit()
    await session.refresh(investigation)

    return InvestigationResponse.model_validate(investigation)


@router.delete("/{investigation_id}", status_code=204)
async def delete_investigation(
    request: Request,
    investigation_id: Annotated[UUID, Path(...)],
    current_user: CurrentUserDep,
    session: TenantSessionDep,
) -> None:
    """Delete an investigation.

    Requires owner role. Admin can also delete.

    Args:
        investigation_id: Investigation UUID from path

    Raises:
        HTTPException 404: Investigation not found or no access
        HTTPException 403: User is not owner
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant context")

    user_role = getattr(request.state, "user_role", None)

    # Check permission
    if user_role != UserRole.admin:
        permission_service = PermissionService(session)
        permission = await permission_service.get_investigation_permission(
            current_user.id, investigation_id
        )

        if permission is None:
            # Log permission not found (AC8, AC12)
            audit_logger = AuditLogger(session, tenant_id)
            ip_address, user_agent = _get_request_metadata(request)
            await audit_logger.log_security_event(
                event_type=PermissionEventType.permission_not_found,
                actor_id=current_user.id,
                investigation_id=investigation_id,
                reason="no_permission_for_investigation",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await session.commit()
            raise HTTPException(status_code=404, detail="Investigation not found")

        if permission.role != InvestigationRole.owner:
            # Log permission denied (AC8, AC12)
            audit_logger = AuditLogger(session, tenant_id)
            ip_address, user_agent = _get_request_metadata(request)
            await audit_logger.log_permission_denied(
                actor_id=current_user.id,
                investigation_id=investigation_id,
                requested_action="delete",
                user_role=permission.role,
                reason="non_owner_cannot_delete",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await session.commit()
            raise HTTPException(status_code=403, detail="Only owner can delete investigation")

    # Fetch and delete investigation
    result = await session.execute(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.tenant_id == tenant_id,
        )
    )
    investigation = result.scalar_one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    await session.delete(investigation)
    await session.commit()
