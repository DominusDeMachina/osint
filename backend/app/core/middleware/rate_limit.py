"""Rate limiting middleware using sliding window algorithm.

Implements Story 1.5: Tier-Based Rate Limiting (AC: 3, 4, 5, 9, 10).

Provides:
- Sliding window rate limiting using Redis sorted sets
- Tier-based limits (free, pro, business, enterprise)
- Standard rate limit headers on all responses
- 429 Too Many Requests with Retry-After header
- Audit logging for rate limit exceeded events (AC8, AC22)
"""

import logging
import time
from typing import TYPE_CHECKING, Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.audit.logger import SimpleAuditLogger


if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = logging.getLogger(__name__)


# Tier-based rate limits (requests per hour) - AC9
TIER_LIMITS: dict[str, int] = {
    "free": 100,
    "pro": 1000,
    "business": 10000,
    "enterprise": 50000,
}

# Default window in seconds (1 hour)
WINDOW_SECONDS = 3600


def get_tier_limit(tier: str | None) -> int:
    """Get rate limit for a subscription tier.

    Args:
        tier: Subscription tier name

    Returns:
        Rate limit for the tier, defaults to free tier
    """
    if tier is None:
        return TIER_LIMITS["free"]
    return TIER_LIMITS.get(tier, TIER_LIMITS["free"])


def create_rate_limit_headers(
    limit: int,
    remaining: int,
    reset_time: int,
    exceeded: bool = False,
) -> dict[str, str]:
    """Create standard rate limit headers.

    Implements AC4: Rate limit headers on all responses.

    Args:
        limit: Maximum requests allowed
        remaining: Requests remaining in window
        reset_time: Unix timestamp when window resets
        exceeded: Whether limit was exceeded (adds Retry-After)

    Returns:
        Dict of header name to value
    """
    headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(reset_time),
    }

    if exceeded:
        # Retry-After should be seconds until reset
        retry_after = max(1, reset_time - int(time.time()))
        headers["Retry-After"] = str(retry_after)

    return headers


def create_rate_limit_error_response(limit: int) -> dict[str, Any]:
    """Create 429 error response body.

    Implements AC5: Error format for rate limit exceeded.

    Args:
        limit: The rate limit that was exceeded

    Returns:
        Error response dict
    """
    return {
        "error": {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": f"Rate limit exceeded. Limit: {limit}/hour",
        }
    }


class SlidingWindowRateLimiter:
    """Sliding window rate limiter using Redis sorted sets.

    Implements AC10: Sliding window algorithm for fair distribution.

    Uses Redis sorted sets to track request timestamps:
    - ZADD adds current request with timestamp as score
    - ZREMRANGEBYSCORE removes old entries outside window
    - ZCARD counts current requests in window
    """

    def __init__(self, redis: "Redis[str]") -> None:
        """Initialize rate limiter.

        Args:
            redis: Redis client instance
        """
        self.redis = redis

    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int = WINDOW_SECONDS,
    ) -> tuple[bool, int, int]:
        """Check if request is within rate limit.

        Uses atomic Redis operations in a pipeline for consistency.

        Args:
            key: Unique identifier for rate limit (e.g., user:123)
            limit: Maximum requests allowed in window
            window_seconds: Time window in seconds

        Returns:
            Tuple of (allowed: bool, remaining: int, reset_time: int)
        """
        now = time.time()
        window_start = now - window_seconds
        reset_time = int(now + window_seconds)

        # Atomic Redis operations in pipeline
        # Note: Pipeline commands are queued, not awaited individually
        async with self.redis.pipeline(transaction=True) as pipe:
            # Remove old entries outside window
            pipe.zremrangebyscore(key, 0, window_start)
            # Count current requests
            pipe.zcard(key)
            # Add current request with timestamp
            pipe.zadd(key, {str(now): now})
            # Set expiry on key
            pipe.expire(key, window_seconds)
            results = await pipe.execute()

        current_count = results[1]  # ZCARD result

        # Calculate remaining (not counting the request we just added)
        remaining = max(0, limit - current_count - 1)

        # Check if over limit
        allowed = current_count < limit

        return allowed, remaining, reset_time


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for tier-based rate limiting.

    Implements AC3, AC4, AC5: Rate limiting with headers and 429 responses.

    Applies rate limits to all /api/ routes based on user tier.
    """

    def __init__(
        self,
        app: Any,
        redis: "Redis[str]",
    ) -> None:
        """Initialize middleware.

        Args:
            app: FastAPI application
            redis: Redis client for rate limit storage
        """
        super().__init__(app)
        self.rate_limiter = SlidingWindowRateLimiter(redis)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request through rate limiting.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response with rate limit headers
        """
        # Skip rate limiting for non-API routes
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        # Get user from request state (set by auth middleware)
        user = getattr(request.state, "user", None)
        if not user:
            # No authenticated user - skip rate limiting
            # (webhook endpoints, health checks, etc.)
            return await call_next(request)

        # Get user ID and tier
        user_id = getattr(user, "id", None)
        if not user_id:
            return await call_next(request)

        tier = getattr(user, "subscription_tier", "free")
        base_limit = get_tier_limit(tier)

        # AC17: Check for risk-based rate limit override
        # Override stored by webhook handler for risky signups
        override_key = f"ratelimit:override:{user_id}"
        override_limit = await self.rate_limiter.redis.get(override_key)
        limit = int(override_limit) if override_limit else base_limit

        # Check rate limit
        key = f"ratelimit:{user_id}"
        allowed, remaining, reset_time = await self.rate_limiter.check_rate_limit(
            key=key, limit=limit, window_seconds=WINDOW_SECONDS
        )

        if not allowed:
            # AC8: Log rate limit exceeded event
            logger.warning(f"Rate limit exceeded for user {user_id} (tier: {tier}, limit: {limit})")
            # AC8: Also log to audit trail for compliance
            audit_logger = SimpleAuditLogger()
            await audit_logger.log_event(
                "rate_limit_exceeded",
                details={
                    "user_id": str(user_id),
                    "tier": tier,
                    "limit": limit,
                    "endpoint": request.url.path,
                },
            )
            # Return 429 Too Many Requests
            headers = create_rate_limit_headers(
                limit=limit,
                remaining=0,
                reset_time=reset_time,
                exceeded=True,
            )
            return JSONResponse(
                status_code=429,
                content=create_rate_limit_error_response(limit),
                headers=headers,
            )

        # AC22: Log rate_limit_threshold_warning when user hits 80% of limit
        usage_percent = ((limit - remaining - 1) / limit) * 100
        if usage_percent >= 80:
            logger.info(
                f"Rate limit threshold warning: user {user_id} at {usage_percent:.0f}% "
                f"({limit - remaining - 1}/{limit}) of {tier} tier limit"
            )
            # AC22: Also log to audit trail for compliance
            audit_logger = SimpleAuditLogger()
            await audit_logger.log_event(
                "rate_limit_threshold_warning",
                details={
                    "user_id": str(user_id),
                    "tier": tier,
                    "limit": limit,
                    "current_usage": limit - remaining - 1,
                    "usage_percent": round(usage_percent, 1),
                    "endpoint": request.url.path,
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers to successful response
        headers = create_rate_limit_headers(
            limit=limit,
            remaining=remaining,
            reset_time=reset_time,
        )
        for name, value in headers.items():
            response.headers[name] = value

        return response
