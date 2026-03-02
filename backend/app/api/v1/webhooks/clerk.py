"""Clerk webhook handler for user synchronization.

Handles Clerk webhook events to sync user data to local database:
- user.created: Create new User, Tenant, and TenantMembership
- user.updated: Sync email/name changes
- user.deleted: Soft delete user

All webhooks are verified using Svix signature verification.
"""

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import select
from svix.webhooks import Webhook, WebhookVerificationError

from app.core.config import settings
from app.core.database import async_session_maker
from app.models.tenant import Tenant
from app.models.user import TenantMembership, User, UserRole


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

    # Verify webhook signature
    headers = {
        "svix-id": svix_id or "",
        "svix-timestamp": svix_timestamp or "",
        "svix-signature": svix_signature or "",
    }

    payload = verify_webhook(body, headers)
    event_type = payload.get("type", "")
    data = payload.get("data", {})

    logger.info(f"Received Clerk webhook: {event_type}")

    if event_type == "user.created":
        await handle_user_created(data)
    elif event_type == "user.updated":
        await handle_user_updated(data)
    elif event_type == "user.deleted":
        await handle_user_deleted(data)
    else:
        logger.info(f"Ignoring unhandled event type: {event_type}")

    return {"status": "ok"}


async def handle_user_created(data: dict[str, Any]) -> None:
    """Handle user.created webhook event.

    Creates:
    1. New User record with Clerk data
    2. New Tenant for the user
    3. TenantMembership linking user to tenant as admin

    Args:
        data: Clerk user data from webhook payload
    """
    clerk_id = data.get("id")
    email_addresses = data.get("email_addresses", [])
    first_name = data.get("first_name") or ""
    last_name = data.get("last_name") or ""
    image_url = data.get("image_url")

    if not clerk_id:
        logger.error("user.created webhook missing user id")
        return

    # Get primary email
    email = None
    for addr in email_addresses:
        email = addr.get("email_address")
        if email:
            break

    if not email:
        logger.error(f"user.created webhook missing email for clerk_id: {clerk_id}")
        return

    # Build name
    name = f"{first_name} {last_name}".strip() or None

    async with async_session_maker() as session:
        # Check if user already exists
        existing = await session.execute(select(User).where(User.clerk_id == clerk_id))
        if existing.scalar_one_or_none():
            logger.info(f"User already exists for clerk_id: {clerk_id}")
            return

        # Create user
        user = User(
            clerk_id=clerk_id,
            email=email,
            name=name,
            avatar_url=image_url,
            is_active=True,
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
