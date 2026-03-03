"""Unit tests for rate limiting middleware.

Tests tier-based rate limiting with sliding window algorithm
per Story 1.5 acceptance criteria (AC: 3, 4, 5, 9, 10).
"""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.middleware.rate_limit import (
    TIER_LIMITS,
    SlidingWindowRateLimiter,
    create_rate_limit_error_response,
    create_rate_limit_headers,
    get_tier_limit,
)


class TestSlidingWindowRateLimiter:
    """Tests for sliding window rate limiter (AC: 3, 10)."""

    @pytest.fixture
    def mock_redis(self) -> AsyncMock:
        """Create mock Redis client."""
        redis = AsyncMock()
        return redis

    @pytest.fixture
    def rate_limiter(self, mock_redis: AsyncMock) -> SlidingWindowRateLimiter:
        """Create SlidingWindowRateLimiter with mocked Redis."""
        return SlidingWindowRateLimiter(redis=mock_redis)

    def _create_pipeline_mock(self, count: int) -> AsyncMock:
        """Create a mock pipeline with proper async context manager."""
        pipeline = MagicMock()
        pipeline.zremrangebyscore = MagicMock(return_value=pipeline)
        pipeline.zcard = MagicMock(return_value=pipeline)
        pipeline.zadd = MagicMock(return_value=pipeline)
        pipeline.expire = MagicMock(return_value=pipeline)
        pipeline.execute = AsyncMock(return_value=[None, count, None, None])
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        return pipeline

    @pytest.mark.asyncio
    async def test_under_limit_allowed(
        self, rate_limiter: SlidingWindowRateLimiter, mock_redis: AsyncMock
    ) -> None:
        """Request under limit should be allowed."""
        pipeline = self._create_pipeline_mock(count=50)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        allowed, remaining, _reset_time = await rate_limiter.check_rate_limit(
            key="user:123", limit=100, window_seconds=3600
        )

        assert allowed is True
        assert remaining == 49  # 100 - 50 - 1 (current request)

    @pytest.mark.asyncio
    async def test_at_limit_blocked(
        self, rate_limiter: SlidingWindowRateLimiter, mock_redis: AsyncMock
    ) -> None:
        """Request at limit should be blocked."""
        pipeline = self._create_pipeline_mock(count=100)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        allowed, remaining, _reset_time = await rate_limiter.check_rate_limit(
            key="user:123", limit=100, window_seconds=3600
        )

        assert allowed is False
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_over_limit_blocked(
        self, rate_limiter: SlidingWindowRateLimiter, mock_redis: AsyncMock
    ) -> None:
        """Request over limit should be blocked."""
        pipeline = self._create_pipeline_mock(count=150)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        allowed, remaining, _reset_time = await rate_limiter.check_rate_limit(
            key="user:123", limit=100, window_seconds=3600
        )

        assert allowed is False
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_reset_time_in_future(
        self, rate_limiter: SlidingWindowRateLimiter, mock_redis: AsyncMock
    ) -> None:
        """Reset time should be window_seconds in future."""
        pipeline = self._create_pipeline_mock(count=50)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        before = int(time.time())
        _allowed, _remaining, reset_time = await rate_limiter.check_rate_limit(
            key="user:123", limit=100, window_seconds=3600
        )
        after = int(time.time())

        assert reset_time >= before + 3600
        assert reset_time <= after + 3600 + 1


class TestTierBasedLimits:
    """Tests for tier-based rate limits (AC: 9)."""

    def test_tier_limits_defined(self) -> None:
        """All tier limits should be defined."""
        assert TIER_LIMITS["free"] == 100
        assert TIER_LIMITS["pro"] == 1000
        assert TIER_LIMITS["business"] == 10000
        assert TIER_LIMITS["enterprise"] == 50000

    def test_default_tier_is_free(self) -> None:
        """Unknown tiers should default to free tier."""
        assert get_tier_limit("unknown") == 100
        assert get_tier_limit(None) == 100

    def test_free_tier_limit_100(self) -> None:
        """Free tier should allow 100 requests/hour."""
        limit = TIER_LIMITS["free"]
        assert limit == 100

    def test_pro_tier_limit_1000(self) -> None:
        """Pro tier should allow 1000 requests/hour."""
        limit = TIER_LIMITS["pro"]
        assert limit == 1000


class TestRateLimitHeaders:
    """Tests for rate limit headers (AC: 4, 5)."""

    def test_rate_limit_headers_structure(self) -> None:
        """Rate limit headers should have correct names."""
        headers = create_rate_limit_headers(limit=100, remaining=50, reset_time=1709500800)

        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "50"
        assert headers["X-RateLimit-Reset"] == "1709500800"

    def test_rate_limit_headers_at_zero(self) -> None:
        """Headers should show 0 remaining when exhausted."""
        headers = create_rate_limit_headers(limit=100, remaining=0, reset_time=1709500800)

        assert headers["X-RateLimit-Remaining"] == "0"

    def test_retry_after_header_on_exceeded(self) -> None:
        """Retry-After header should be set when limit exceeded."""
        headers = create_rate_limit_headers(
            limit=100, remaining=0, reset_time=1709500800, exceeded=True
        )

        assert "Retry-After" in headers
        assert int(headers["Retry-After"]) > 0


class TestRateLimitErrorResponse:
    """Tests for 429 error response format (AC: 5)."""

    def test_429_response_format(self) -> None:
        """429 response should have correct format."""
        response = create_rate_limit_error_response(limit=100)

        assert response["error"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert "100" in response["error"]["message"]
