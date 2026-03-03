"""GDPR compliance endpoints.

Implements Story 1.5: GDPR Compliance (AC21, AC25).

Provides:
- IP data deletion endpoint for user privacy requests
- Rate limiting to prevent abuse of GDPR endpoint
- Signup review queue management (AC26)
"""

import hashlib
import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import update
from sqlmodel import select

from app.audit.logger import SimpleAuditLogger
from app.core.database import async_session_maker
from app.core.redis import get_redis
from app.models.audit import AuditLog
from app.models.user import User, UserRole
from app.services.anti_abuse import GDPRRateLimiter, ServerSideTiming, SignupReviewQueue


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gdpr", tags=["GDPR"])


# =============================================================================
# Authentication Dependencies
# =============================================================================


async def get_current_user_from_request(request: Request) -> User | None:
    """Extract current user from request state.

    The auth middleware sets request.state.user for authenticated requests.

    Args:
        request: FastAPI request object

    Returns:
        User object if authenticated, None otherwise
    """
    return getattr(request.state, "user", None)


async def require_authenticated_user(request: Request) -> User:
    """Require authenticated user for endpoint access.

    Args:
        request: FastAPI request object

    Returns:
        Authenticated User object

    Raises:
        HTTPException: 401 if not authenticated
    """
    user = await get_current_user_from_request(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )
    return user


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request headers.

    Args:
        request: FastAPI request object

    Returns:
        Client IP address string
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip

    return request.client.host if request.client else "unknown"


def _hash_ip_for_log(ip: str) -> str:
    """Hash IP for logging (privacy-preserving).

    Args:
        ip: Raw IP address

    Returns:
        Truncated hash of IP
    """
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


# Type alias for authenticated user dependency
AuthenticatedUser = Annotated[User, Depends(require_authenticated_user)]


@router.delete("/ip-data/{user_id}")
async def delete_ip_data(
    user_id: UUID,
    request: Request,
    current_user: AuthenticatedUser,
) -> Response:
    """Delete all IP-related data for GDPR compliance.

    Implements AC21: GDPR compliance endpoint for IP hash data deletion.
    Implements AC25: Rate limiting on GDPR endpoint (30-day cooldown).

    Can only be called by:
    - The user themselves (self-service deletion)
    - Admin users (support request)

    Args:
        user_id: UUID of the user whose IP data should be deleted
        request: FastAPI request object
        current_user: Authenticated user from dependency

    Returns:
        204 No Content on success

    Raises:
        HTTPException: 401 if not authenticated, 403 if not authorized,
                      404 if user not found, 429 if rate limited
    """
    audit_logger = SimpleAuditLogger()
    redis = await get_redis()

    # AC21: Authorization check - user can only delete their own data, or admin can delete any
    is_self_request = str(current_user.id) == str(user_id)
    # Check if user has admin role in any tenant
    is_admin = any(m.role == UserRole.admin for m in getattr(current_user, "memberships", []))

    if not is_self_request and not is_admin:
        await audit_logger.log_event(
            "gdpr_unauthorized_attempt",
            details={
                "user_id": str(user_id),
                "requester_id": str(current_user.id),
                "requester_role": str(getattr(current_user, "global_role", "unknown")),
            },
        )
        raise HTTPException(
            status_code=403,
            detail="Not authorized to delete this user's data",
        )

    # AC25: Check GDPR endpoint rate limit
    client_ip = _get_client_ip(request)
    gdpr_limiter = GDPRRateLimiter(redis)

    allowed, remaining_seconds = await gdpr_limiter.check_rate_limit(client_ip)
    if not allowed:
        # Calculate remaining days
        remaining_days = (remaining_seconds or 0) // 86400

        await audit_logger.log_event(
            "gdpr_rate_limited",
            details={
                "user_id": str(user_id),
                "requester_id": str(current_user.id),
                "remaining_seconds": remaining_seconds,
            },
        )

        raise HTTPException(
            status_code=429,
            detail=f"GDPR deletion rate limited. Try again in {remaining_days} days.",
            headers={"Retry-After": str(remaining_seconds)},
        )

    async with async_session_maker() as session:
        # Find target user
        result = await session.execute(select(User).where(User.id == user_id))
        target_user = result.scalar_one_or_none()

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Delete IP data from Redis if signup_ip_hash is stored
        signup_ip_hash = target_user.signup_ip_hash
        ip_data_deleted = False
        audit_logs_anonymized = 0

        if signup_ip_hash:
            # Delete the IP account counter from Redis
            ip_key = f"ip:accounts:{signup_ip_hash}"
            await redis.delete(ip_key)
            ip_data_deleted = True

            # HIGH-1 fix: Anonymize IP addresses in audit logs (GDPR compliance)
            # We anonymize rather than delete to preserve audit trail integrity
            # Set ip_address to "[GDPR_DELETED]" for all logs with this IP hash
            update_stmt = (
                update(AuditLog)
                .where(AuditLog.actor_id == user_id)  # type: ignore[arg-type]
                .where(AuditLog.ip_address.isnot(None))  # type: ignore[union-attr]
                .values(ip_address="[GDPR_DELETED]")
            )
            update_result = await session.execute(update_stmt)
            audit_logs_anonymized = getattr(update_result, "rowcount", 0) or 0

            # Clear the hash from user record
            target_user.signup_ip_hash = None
            await session.commit()

        await audit_logger.log_event(
            "gdpr_ip_data_deleted",
            details={
                "user_id": str(user_id),
                "requester_id": str(current_user.id),
                "is_admin_request": is_admin,
                "ip_data_found": ip_data_deleted,
                "audit_logs_anonymized": audit_logs_anonymized,
                "requested_by_ip_hash": _hash_ip_for_log(client_ip),
            },
        )

        logger.info(
            f"GDPR IP data deletion completed for user {user_id} "
            f"(ip_data_deleted={ip_data_deleted}, audit_logs_anonymized={audit_logs_anonymized})"
        )

    # Record this deletion for rate limiting
    await gdpr_limiter.record_deletion(client_ip)

    return Response(status_code=204)


@router.post("/timing/start")
async def start_timing_session() -> JSONResponse:
    """Start server-side timing session for bot detection.

    Implements AC19: Server-side form timing.

    Call this endpoint when the signup page loads to start
    tracking form fill time on the server side.

    Returns:
        Response with timing session ID in cookie
    """
    redis = await get_redis()
    timing = ServerSideTiming(redis)
    session_id = await timing.start_session()

    response = JSONResponse({"status": "ok", "session_id": session_id})
    response.set_cookie(
        "timing_session",
        session_id,
        httponly=True,
        secure=True,  # Require HTTPS in production
        samesite="strict",
        max_age=3600,
    )
    return response


# =============================================================================
# Admin Endpoints for Review Queue (AC26)
# =============================================================================

# Create a separate router for admin endpoints
admin_router = APIRouter(prefix="/admin/review-queue", tags=["Admin - Review Queue"])


async def require_admin_user(request: Request) -> User:
    """Require admin user for endpoint access.

    Args:
        request: FastAPI request object

    Returns:
        Authenticated admin User object

    Raises:
        HTTPException: 401 if not authenticated, 403 if not admin
    """
    user = await require_authenticated_user(request)
    # Check if user has admin role in any tenant
    is_admin = any(m.role == UserRole.admin for m in getattr(user, "memberships", []))
    if not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )
    return user


# Type alias for admin user dependency
AdminUser = Annotated[User, Depends(require_admin_user)]


@admin_router.get("")
async def get_review_queue(
    _current_user: AdminUser,
    limit: int = 50,
) -> dict[str, Any]:
    """Get pending signups in the review queue.

    Implements AC26: Admin endpoint to process review queue.

    Args:
        _current_user: Authenticated admin user (used for authorization)
        limit: Maximum number of items to return (default 50)

    Returns:
        List of pending signups awaiting review
    """
    redis = await get_redis()
    review_queue = SignupReviewQueue(redis)

    items = await review_queue.get_items(limit=limit)
    queue_length = await review_queue.get_queue_length()

    return {
        "items": items,
        "total": queue_length,
        "returned": len(items),
    }


@admin_router.post("/{clerk_id}/approve")
async def approve_signup(
    clerk_id: str,
    current_user: AdminUser,
) -> dict[str, str]:
    """Approve a signup from the review queue.

    Implements AC26: Manual review of flagged signups.

    Args:
        clerk_id: Clerk user ID of the signup to approve
        current_user: Authenticated admin user

    Returns:
        Success message
    """
    audit_logger = SimpleAuditLogger()
    redis = await get_redis()
    review_queue = SignupReviewQueue(redis)

    # Find and remove the item from the queue
    item = await review_queue.remove_item(clerk_id)

    if not item:
        raise HTTPException(
            status_code=404,
            detail=f"Signup with clerk_id {clerk_id} not found in review queue",
        )

    # Activate the user if needed
    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.clerk_id == clerk_id))
        user = result.scalar_one_or_none()
        if user and not user.is_active:
            user.is_active = True
            await session.commit()
            logger.info(f"Activated user {user.id} after manual review")

    await audit_logger.log_event(
        "signup_review_approved",
        details={
            "clerk_id": clerk_id,
            "approved_by": str(current_user.id),
            "original_reason": item.get("reason"),
        },
    )

    return {"status": "approved", "clerk_id": clerk_id}


@admin_router.post("/{clerk_id}/reject")
async def reject_signup(
    clerk_id: str,
    current_user: AdminUser,
    reason: str = "Manual rejection by admin",
) -> dict[str, str]:
    """Reject a signup from the review queue.

    Implements AC26: Manual review of flagged signups.

    Args:
        clerk_id: Clerk user ID of the signup to reject
        current_user: Authenticated admin user
        reason: Reason for rejection

    Returns:
        Success message
    """
    audit_logger = SimpleAuditLogger()
    redis = await get_redis()
    review_queue = SignupReviewQueue(redis)

    # Find and remove the item from the queue
    item = await review_queue.remove_item(clerk_id)

    if not item:
        raise HTTPException(
            status_code=404,
            detail=f"Signup with clerk_id {clerk_id} not found in review queue",
        )

    # Deactivate the user
    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.clerk_id == clerk_id))
        user = result.scalar_one_or_none()
        if user:
            user.is_active = False
            await session.commit()
            logger.info(f"Deactivated user {user.id} after manual rejection")

    await audit_logger.log_event(
        "signup_review_rejected",
        details={
            "clerk_id": clerk_id,
            "rejected_by": str(current_user.id),
            "rejection_reason": reason,
            "original_reason": item.get("reason"),
        },
    )

    return {"status": "rejected", "clerk_id": clerk_id, "reason": reason}
