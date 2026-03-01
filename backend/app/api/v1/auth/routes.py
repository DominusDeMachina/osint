"""Authentication API routes."""

from fastapi import APIRouter, Request
from sqlmodel import select

from app.api.deps import CurrentUserDep, SessionDep
from app.api.v1.auth.schemas import TenantInfo, UserResponse
from app.models.tenant import Tenant


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    request: Request,
    user: CurrentUserDep,
    db: SessionDep,
) -> UserResponse:
    """Get current authenticated user information.

    Returns the user's profile including their tenant and role.
    Requires a valid Clerk JWT in the Authorization header.

    Returns:
        UserResponse: Current user profile with tenant info
    """
    # Get tenant info from request state (set by get_current_user)
    tenant_id = getattr(request.state, "tenant_id", None)
    user_role = getattr(request.state, "user_role", None)

    tenant_info = None
    if tenant_id:
        result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = result.scalar_one_or_none()
        if tenant:
            tenant_info = TenantInfo(id=tenant.id, name=tenant.name)

    return UserResponse(
        id=user.id,
        clerk_id=user.clerk_id,
        email=user.email,
        name=user.name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        tenant=tenant_info,
        role=str(user_role) if user_role else None,
    )
