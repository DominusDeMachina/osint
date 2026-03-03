"""Clerk webhook handler for user synchronization.

Handles Clerk webhook events to sync user data to local database:
- user.created: Create new User, Tenant, and TenantMembership
- user.updated: Sync email/name changes
- user.deleted: Soft delete user

All webhooks are verified using Svix signature verification.

Story 1.5 Integration:
- Anti-abuse checks before user creation (AC11)
- IP account limiting (AC1)
- Business email validation (AC2)
- Audit logging for blocked signups (AC8)
"""

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import select
from svix.webhooks import Webhook, WebhookVerificationError

from app.audit.logger import SimpleAuditLogger
from app.core.config import settings
from app.core.database import async_session_maker
from app.core.redis import get_redis
from app.models.tenant import Tenant
from app.models.user import TenantMembership, User, UserRole
from app.services.anti_abuse import (
    AntiAbuseService,
    RiskLevel,
    ServerSideTiming,
    SignupReviewItem,
    SignupReviewQueue,
    SignupVelocityMonitor,
    WebhookIdempotency,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


class ClerkEmailAddress(BaseModel):
    """Clerk email address object."""

    email_address: str
    id: str


class ClerkUserData(BaseModel):
    """Clerk user data from webhook payload."""

    id: str
    email_addresses: list[ClerkEmailAddress] = []
    first_name: str | None = None
    last_name: str | None = None
    image_url: str | None = None


class ClerkWebhookPayload(BaseModel):
    """Clerk webhook payload structure."""

    type: str
    data: dict[str, Any]


def verify_webhook(payload: bytes, headers: dict[str, str]) -> dict[str, Any]:
    """Verify Clerk webhook signature using Svix.

    Args:
        payload: Raw request body bytes
        headers: Request headers containing Svix signature

    Returns:
        Verified and parsed webhook payload

    Raises:
        HTTPException: 400 if signature verification fails
    """
    webhook_secret = settings.clerk_webhook_secret

    if not webhook_secret:
        raise HTTPException(
            status_code=500,
            detail="Webhook secret not configured",
        )

    try:
        wh = Webhook(webhook_secret)
        result: dict[str, Any] = wh.verify(payload, headers)
        return result
    except WebhookVerificationError as e:
        logger.warning(f"Webhook verification failed: {e}")
        raise HTTPException(
            status_code=400,
            detail="Invalid webhook signature",
        ) from e


@router.post("/clerk")
async def handle_clerk_webhook(
    request: Request,
    svix_id: str = Header(None, alias="svix-id"),
    svix_timestamp: str = Header(None, alias="svix-timestamp"),
    svix_signature: str = Header(None, alias="svix-signature"),
) -> dict[str, str]:
    """Handle incoming Clerk webhooks.

    Processes user lifecycle events from Clerk:
    - user.created: Creates user, tenant, and membership
    - user.updated: Updates user email/name
    - user.deleted: Soft deletes user

    Implements:
    - AC23: Webhook idempotency (reject duplicate svix-id)
    - AC20: Svix signature verification (via svix library)

    Args:
        request: FastAPI request object
        svix_id: Svix webhook ID header
        svix_timestamp: Svix timestamp header
        svix_signature: Svix signature header

    Returns:
        Success acknowledgment
    """
    # Get raw body for signature verification
    body = await request.body()

    # Initialize audit logger for security events
    audit_logger = SimpleAuditLogger()

    # AC23: Check webhook idempotency FIRST (before expensive signature verification)
    redis = await get_redis()
    idempotency = WebhookIdempotency(redis)

    if await idempotency.is_duplicate(svix_id):
        logger.warning(f"Duplicate webhook rejected: svix_id={svix_id}")
        # AC22: Log duplicate webhook attempt
        await audit_logger.log_event(
            "webhook_duplicate_rejected",
            details={"svix_id": svix_id},
        )
        raise HTTPException(
            status_code=409,
            detail="Webhook already processed",
        )

    # Verify webhook signature
    headers = {
        "svix-id": svix_id or "",
        "svix-timestamp": svix_timestamp or "",
        "svix-signature": svix_signature or "",
    }

    try:
        payload = verify_webhook(body, headers)
    except HTTPException as e:
        # AC22: Log webhook signature invalid event
        await audit_logger.log_event(
            "webhook_signature_invalid",
            details={
                "svix_id": svix_id,
                "error": str(e.detail),
            },
        )
        raise

    event_type = payload.get("type", "")
    data = payload.get("data", {})

    logger.info(f"Received Clerk webhook: {event_type}")

    if event_type == "user.created":
        # Pass request for IP extraction (AC11)
        result = await handle_user_created(data, request)
        return {"status": result.get("status", "ok") if result else "ok"}
    elif event_type == "user.updated":
        await handle_user_updated(data)
    elif event_type == "user.deleted":
        await handle_user_deleted(data)
    else:
        logger.info(f"Ignoring unhandled event type: {event_type}")

    return {"status": "ok"}


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request headers.

    Checks X-Forwarded-For, X-Real-IP, then falls back to client.host.
    Clerk forwards original client IP in headers.

    Args:
        request: FastAPI request object

    Returns:
        Client IP address string
    """
    # X-Forwarded-For may contain multiple IPs, take the first (original client)
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    # X-Real-IP is typically set by reverse proxies
    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip

    # Fall back to direct client
    return request.client.host if request.client else "unknown"


async def handle_user_created(  # noqa: PLR0912, PLR0915
    data: dict[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    """Handle user.created webhook event.

    Implements AC11: Anti-abuse checks before user creation.

    Creates:
    1. Run anti-abuse checks (IP limit, email validation)
    2. New User record with Clerk data
    3. New Tenant for the user
    4. TenantMembership linking user to tenant as admin
    5. Record signup IP for future checks

    Args:
        data: Clerk user data from webhook payload
        request: FastAPI request for IP extraction

    Returns:
        Result dict with status and any errors

    Raises:
        HTTPException: 400 if anti-abuse checks fail
    """
    clerk_id = data.get("id")
    email_addresses = data.get("email_addresses", [])
    first_name = data.get("first_name") or ""
    last_name = data.get("last_name") or ""
    image_url = data.get("image_url")

    if not clerk_id:
        logger.error("user.created webhook missing user id")
        return {"status": "error", "message": "Missing user id"}

    # Get primary email
    email = None
    for addr in email_addresses:
        email = addr.get("email_address")
        if email:
            break

    if not email:
        logger.error(f"user.created webhook missing email for clerk_id: {clerk_id}")
        return {"status": "error", "message": "Missing email"}

    # Extract client IP for anti-abuse checks
    client_ip = _get_client_ip(request) if request else "unknown"

    # Initialize anti-abuse service
    redis = await get_redis()
    audit_logger = SimpleAuditLogger()
    anti_abuse = AntiAbuseService(redis=redis, audit_logger=audit_logger)

    # AC26: Check signup velocity before processing
    velocity_monitor = SignupVelocityMonitor(redis, audit_logger)
    velocity_ok, velocity_count = await velocity_monitor.record_signup()
    requires_manual_review = False
    if not velocity_ok:
        logger.warning(f"Signup velocity exceeded: {velocity_count}/min for clerk_id: {clerk_id}")
        # Don't block, but flag for review (per AC26)
        requires_manual_review = True

    # AC2, AC7, AC18, AC24: Validate business email with normalization
    email_allowed, email_error, normalized_email = anti_abuse.validate_business_email(email)

    # AC18: Log if normalization changed the email (potential bypass attempt)
    if normalized_email != email.lower():
        await audit_logger.log_event(
            "email_normalization_applied",
            details={
                "clerk_id": clerk_id,
                "original_domain": email.split("@")[-1],
                "normalized_domain": normalized_email.split("@")[-1],
            },
        )

    if not email_allowed:
        email_domain = normalized_email.split("@")[-1]
        logger.warning(f"Signup blocked - email domain: {email_domain} for clerk_id: {clerk_id}")
        # AC8: Audit log for blocked email signup
        await audit_logger.log_event(
            "signup_blocked_email",
            details={
                "clerk_id": clerk_id,
                "email_domain": email_domain,
                "reason": email_error,
            },
        )
        raise HTTPException(
            status_code=400,
            detail={"code": "SIGNUP_BLOCKED", "message": email_error},
        )

    # AC12, AC16, AC17: Calculate multi-signal risk score
    # AC19: Get form timing from server-side session (not client header!)
    # NOTE: Clerk webhooks do NOT include client cookies - timing data must be passed
    # via custom headers or metadata in the Clerk user object
    form_timing_seconds: float | None = None

    # Try to get timing from Clerk user metadata (set during frontend signup)
    user_metadata = data.get("public_metadata", {}) or data.get("unsafe_metadata", {})
    timing_session_id = user_metadata.get("timing_session_id")

    if timing_session_id:
        # Use server-side timing (unforgeable)
        server_timing = ServerSideTiming(redis)
        form_timing_seconds = await server_timing.get_elapsed_time(timing_session_id)
        if form_timing_seconds is not None:
            logger.debug(f"Server-side timing: {form_timing_seconds}s for clerk_id: {clerk_id}")
        else:
            logger.debug(f"Timing session not found or expired for clerk_id: {clerk_id}")
    else:
        # Fallback to X-Form-Timing header (less secure, from frontend)
        # AC19: Client header is spoofable - add risk penalty for missing server timing
        form_timing_header = request.headers.get("X-Form-Timing") if request else None
        if form_timing_header:
            try:
                form_timing_seconds = float(form_timing_header)
                logger.info(f"Using client-side timing (spoofable) for clerk_id: {clerk_id}")
            except ValueError:
                pass
        # If no timing at all, form_timing_seconds stays None → +10 risk in scoring
        # This is expected for Clerk webhooks without frontend timing integration

    user_agent = request.headers.get("User-Agent") if request else None

    risk_score, risk_level, risk_details = await anti_abuse.calculate_signup_risk(
        ip=client_ip,
        email=email,
        form_timing_seconds=form_timing_seconds,
        user_agent=user_agent,
    )

    # AC17: Graduated response based on risk level
    if risk_level == RiskLevel.CRITICAL:
        logger.warning(
            f"Signup blocked - critical risk score {risk_score} for clerk_id: {clerk_id}"
        )
        raise HTTPException(
            status_code=400,
            detail={
                "code": "SIGNUP_BLOCKED",
                "message": "Signup blocked due to security concerns",
                "risk_score": risk_score,
            },
        )

    # AC1, AC6, AC13: Check IP account limit (with datacenter detection)
    ip_allowed, ip_error = await anti_abuse.check_ip_account_limit(
        client_ip, is_datacenter=risk_details.get("is_datacenter")
    )
    if not ip_allowed:
        logger.warning(f"Signup blocked - IP limit reached for clerk_id: {clerk_id}")
        raise HTTPException(
            status_code=400,
            detail={"code": "SIGNUP_BLOCKED", "message": ip_error},
        )

    # Determine if additional verification needed (AC12)
    # HIGH risk users are created with is_active=False until verified
    requires_verification = risk_level == RiskLevel.HIGH
    if requires_verification:
        logger.info(
            f"Signup requires verification - high risk score {risk_score} for clerk_id: {clerk_id}"
        )
        # Log audit event for verification-required signup
        await audit_logger.log_event(
            "signup_requires_verification",
            details={
                "clerk_id": clerk_id,
                "risk_score": risk_score,
                "risk_level": risk_level.value,
            },
        )

    # Build name
    name = f"{first_name} {last_name}".strip() or None

    async with async_session_maker() as session:
        # Check if user already exists
        existing = await session.execute(select(User).where(User.clerk_id == clerk_id))
        if existing.scalar_one_or_none():
            logger.info(f"User already exists for clerk_id: {clerk_id}")
            return {"status": "ok", "message": "User already exists"}

        # Create user (AC12: HIGH risk users are inactive until verified)
        # AC21/HIGH-2 fix: Store signup_ip_hash for GDPR compliance
        ip_hash = risk_details.get("ip_hash")
        user = User(
            clerk_id=clerk_id,
            email=email,
            name=name,
            avatar_url=image_url,
            is_active=not requires_verification,  # False for HIGH risk
            signup_ip_hash=ip_hash,  # For GDPR IP data deletion
        )
        session.add(user)
        await session.flush()  # Get user.id

        # Create tenant for the user
        tenant_name = name or email.split("@")[0]
        tenant = Tenant(
            name=f"{tenant_name}'s Workspace",
            is_active=True,
        )
        session.add(tenant)
        await session.flush()  # Get tenant.id

        # Create membership with admin role
        membership = TenantMembership(
            user_id=user.id,
            tenant_id=tenant.id,
            role=UserRole.admin,
        )
        session.add(membership)

        await session.commit()
        logger.info(f"Created user {user.id} with tenant {tenant.id}")

    # AC6: Record signup IP for future checks
    await anti_abuse.record_signup_ip(client_ip)

    # AC17: Apply graduated response - store rate limit override in Redis
    response = anti_abuse.get_graduated_response(risk_level)
    graduated_rate_limit = response["rate_limit"]

    # If rate limit is reduced (not default 100), store override in Redis
    if graduated_rate_limit < 100:
        override_key = f"ratelimit:override:{user.id}"
        # Store for 30 days (same as IP tracking TTL)
        await redis.set(override_key, str(graduated_rate_limit), ex=30 * 24 * 60 * 60)
        logger.info(
            f"Applied graduated rate limit {graduated_rate_limit}/hr for user {user.id} (risk: {risk_level.value})"
        )

    # AC26: Add to review queue if velocity exceeded
    if requires_manual_review:
        review_queue = SignupReviewQueue(redis, audit_logger)
        review_item = SignupReviewItem(
            clerk_id=clerk_id,
            email=email,
            ip_hash=risk_details.get("ip_hash", "unknown"),
            reason="velocity_exceeded",
            risk_score=risk_score,
            risk_level=risk_level.value,
            velocity_count=velocity_count,
        )
        await review_queue.add_to_queue(review_item)
        logger.info(f"Added signup to review queue: {clerk_id} (velocity: {velocity_count}/min)")

    return {
        "status": "ok",
        "user_id": str(user.id),
        "risk_level": risk_level.value,
        "risk_score": risk_score,
        "requires_verification": requires_verification,
        "requires_manual_review": requires_manual_review,
        "rate_limit": graduated_rate_limit,
    }


async def handle_user_updated(data: dict[str, Any]) -> None:
    """Handle user.updated webhook event.

    Syncs email and name changes from Clerk to local database.

    Args:
        data: Clerk user data from webhook payload
    """
    clerk_id = data.get("id")
    email_addresses = data.get("email_addresses", [])
    first_name = data.get("first_name") or ""
    last_name = data.get("last_name") or ""
    image_url = data.get("image_url")

    if not clerk_id:
        logger.error("user.updated webhook missing user id")
        return

    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.clerk_id == clerk_id))
        user = result.scalar_one_or_none()

        if not user:
            logger.warning(f"User not found for clerk_id: {clerk_id}")
            return

        # Update email if changed
        for addr in email_addresses:
            new_email = addr.get("email_address")
            if new_email and new_email != user.email:
                user.email = new_email
                break

        # Update name
        new_name = f"{first_name} {last_name}".strip() or None
        if new_name != user.name:
            user.name = new_name

        # Update avatar
        if image_url != user.avatar_url:
            user.avatar_url = image_url

        await session.commit()
        logger.info(f"Updated user {user.id}")


async def handle_user_deleted(data: dict[str, Any]) -> None:
    """Handle user.deleted webhook event.

    Soft deletes the user by setting is_active=False.

    Args:
        data: Clerk user data from webhook payload
    """
    clerk_id = data.get("id")

    if not clerk_id:
        logger.error("user.deleted webhook missing user id")
        return

    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.clerk_id == clerk_id))
        user = result.scalar_one_or_none()

        if not user:
            logger.warning(f"User not found for deletion, clerk_id: {clerk_id}")
            return

        user.is_active = False
        await session.commit()
        logger.info(f"Soft deleted user {user.id}")
