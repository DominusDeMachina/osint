"""Integration tests for rate limiting middleware.

Tests end-to-end rate limiting behavior including headers,
429 responses, and tier-based limits.

Story 1.5: Free Tier Anti-Abuse Controls (AC: 3, 4, 5, 9, 10)
"""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.datastructures import URL
from starlette.responses import Response

from app.core.middleware.rate_limit import (
    TIER_LIMITS,
    RateLimitMiddleware,
    SlidingWindowRateLimiter,
    create_rate_limit_error_response,
    create_rate_limit_headers,
    get_tier_limit,
)


class TestRateLimitHeaders:
    """Tests for rate limit headers on API responses (AC: 4)."""

    def test_rate_limit_headers_present(self):
        """Rate limit headers should be present on all API responses."""
        headers = create_rate_limit_headers(
            limit=100,
            remaining=99,
            reset_time=int(time.time()) + 3600,
        )

        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers

    def test_rate_limit_headers_values_correct(self):
        """Rate limit header values should be correctly formatted."""
        reset_time = int(time.time()) + 3600
        headers = create_rate_limit_headers(
            limit=100,
            remaining=50,
            reset_time=reset_time,
        )

        assert headers["X-RateLimit-Limit"] == "100"
        assert headers["X-RateLimit-Remaining"] == "50"
        assert headers["X-RateLimit-Reset"] == str(reset_time)

    def test_retry_after_header_on_exceeded(self):
        """Retry-After header should be present when limit exceeded (AC5)."""
        reset_time = int(time.time()) + 3600
        headers = create_rate_limit_headers(
            limit=100,
            remaining=0,
            reset_time=reset_time,
            exceeded=True,
        )

        assert "Retry-After" in headers
        retry_after = int(headers["Retry-After"])
        assert retry_after > 0
        assert retry_after <= 3600


class TestRateLimitErrorResponse:
    """Tests for 429 error response format (AC: 5)."""

    def test_429_response_has_error_structure(self):
        """429 response should have proper error structure."""
        response = create_rate_limit_error_response(limit=100)

        assert "error" in response
        assert "code" in response["error"]
        assert "message" in response["error"]

    def test_429_response_code(self):
        """429 response should have RATE_LIMIT_EXCEEDED code."""
        response = create_rate_limit_error_response(limit=100)

        assert response["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    def test_429_response_message_includes_limit(self):
        """429 response message should include the rate limit."""
        response = create_rate_limit_error_response(limit=100)

        assert "100" in response["error"]["message"]


class TestTierBasedLimits:
    """Tests for tier-based rate limits (AC: 9)."""

    def test_free_tier_limit(self):
        """Free tier should have 100 requests/hour limit."""
        assert TIER_LIMITS["free"] == 100

    def test_pro_tier_limit(self):
        """Pro tier should have 1000 requests/hour limit."""
        assert TIER_LIMITS["pro"] == 1000

    def test_business_tier_limit(self):
        """Business tier should have 10000 requests/hour limit."""
        assert TIER_LIMITS["business"] == 10000

    def test_enterprise_tier_limit(self):
        """Enterprise tier should have 50000 requests/hour limit."""
        assert TIER_LIMITS["enterprise"] == 50000

    def test_unknown_tier_defaults_to_free(self):
        """Unknown tiers should default to free tier limit."""
        assert get_tier_limit("unknown") == 100
        assert get_tier_limit(None) == 100


class TestSlidingWindowAlgorithm:
    """Tests for sliding window rate limiting algorithm (AC: 10)."""

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        redis = AsyncMock()
        return redis

    def _create_pipeline_mock(self, count: int) -> MagicMock:
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
    async def test_sliding_window_uses_sorted_set(self, mock_redis: AsyncMock):
        """Sliding window should use Redis sorted sets."""
        pipeline = self._create_pipeline_mock(count=50)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        rate_limiter = SlidingWindowRateLimiter(redis=mock_redis)
        await rate_limiter.check_rate_limit(key="user:123", limit=100)

        # Verify sorted set operations were called
        pipeline.zremrangebyscore.assert_called_once()
        pipeline.zcard.assert_called_once()
        pipeline.zadd.assert_called_once()

    @pytest.mark.asyncio
    async def test_sliding_window_removes_old_entries(self, mock_redis: AsyncMock):
        """Sliding window should remove entries outside the window."""
        pipeline = self._create_pipeline_mock(count=50)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        rate_limiter = SlidingWindowRateLimiter(redis=mock_redis)
        await rate_limiter.check_rate_limit(key="user:123", limit=100, window_seconds=3600)

        # zremrangebyscore removes entries older than window_seconds ago
        call_args = pipeline.zremrangebyscore.call_args[0]
        assert call_args[0] == "user:123"  # key
        assert call_args[1] == 0  # min score

    @pytest.mark.asyncio
    async def test_sliding_window_sets_expiry(self, mock_redis: AsyncMock):
        """Sliding window should set key expiry equal to window."""
        pipeline = self._create_pipeline_mock(count=50)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        rate_limiter = SlidingWindowRateLimiter(redis=mock_redis)
        await rate_limiter.check_rate_limit(key="user:123", limit=100, window_seconds=3600)

        # expire should be called with key and window_seconds
        pipeline.expire.assert_called_once_with("user:123", 3600)


class TestRateLimitMiddlewareIntegration:
    """Integration tests for RateLimitMiddleware with FastAPI.

    Note: These tests verify the middleware behavior in isolation.
    The middleware runs before other custom middleware, so user context
    must be set by middleware added AFTER RateLimitMiddleware (which runs first
    due to how Starlette processes middleware stack - last added runs first).
    """

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        redis = AsyncMock()
        return redis

    def _create_pipeline_mock(self, count: int) -> MagicMock:
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

    def test_middleware_skips_non_api_routes(self, mock_redis: AsyncMock):
        """Middleware should skip rate limiting for non-API routes."""
        app = FastAPI()

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        app.add_middleware(RateLimitMiddleware, redis=mock_redis)
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200
        # No rate limit headers on non-API routes
        assert "X-RateLimit-Limit" not in response.headers

    def test_middleware_skips_unauthenticated_requests(self, mock_redis: AsyncMock):
        """Middleware should skip rate limiting for unauthenticated requests."""
        app = FastAPI()

        @app.get("/api/v1/test")
        async def test_endpoint():
            return {"status": "ok"}

        app.add_middleware(RateLimitMiddleware, redis=mock_redis)
        client = TestClient(app)

        response = client.get("/api/v1/test")

        # Request succeeds without auth
        assert response.status_code == 200
        # No rate limit headers without user context
        assert "X-RateLimit-Limit" not in response.headers

    @pytest.mark.asyncio
    async def test_middleware_adds_headers_for_authenticated_requests(self, mock_redis: AsyncMock):
        """Middleware should add rate limit headers for authenticated API requests."""
        pipeline = self._create_pipeline_mock(count=10)
        mock_redis.pipeline = MagicMock(return_value=pipeline)
        # AC17: No rate limit override for this user
        mock_redis.get = AsyncMock(return_value=None)

        # Test the middleware dispatch method directly
        middleware = RateLimitMiddleware(app=None, redis=mock_redis)

        # Create mock request with user
        mock_request = MagicMock(spec=Request)
        mock_request.url = URL("/api/v1/test")
        mock_request.state = MagicMock()
        mock_request.state.user = MagicMock()
        mock_request.state.user.id = "user123"
        mock_request.state.user.subscription_tier = "free"

        async def mock_call_next(_request):
            return Response(content=b'{"status": "ok"}', status_code=200)

        response = await middleware.dispatch(mock_request, mock_call_next)

        assert response.status_code == 200
        assert "X-RateLimit-Limit" in response.headers
        assert response.headers["X-RateLimit-Limit"] == "100"  # Free tier

    @pytest.mark.asyncio
    async def test_middleware_returns_429_when_limit_exceeded(self, mock_redis: AsyncMock):
        """Middleware should return 429 when rate limit is exceeded."""
        # Simulate being at the limit
        pipeline = self._create_pipeline_mock(count=100)
        mock_redis.pipeline = MagicMock(return_value=pipeline)
        # AC17: No rate limit override for this user
        mock_redis.get = AsyncMock(return_value=None)

        middleware = RateLimitMiddleware(app=None, redis=mock_redis)

        mock_request = MagicMock(spec=Request)
        mock_request.url = URL("/api/v1/test")
        mock_request.state = MagicMock()
        mock_request.state.user = MagicMock()
        mock_request.state.user.id = "user123"
        mock_request.state.user.subscription_tier = "free"

        async def mock_call_next(_request):
            return Response(content=b'{"status": "ok"}', status_code=200)

        response = await middleware.dispatch(mock_request, mock_call_next)

        assert response.status_code == 429
        assert "Retry-After" in response.headers

    @pytest.mark.asyncio
    async def test_middleware_uses_correct_tier_limit(self, mock_redis: AsyncMock):
        """Middleware should use the correct limit based on user's subscription tier."""
        pipeline = self._create_pipeline_mock(count=10)
        mock_redis.pipeline = MagicMock(return_value=pipeline)
        # AC17: No rate limit override for this user
        mock_redis.get = AsyncMock(return_value=None)

        middleware = RateLimitMiddleware(app=None, redis=mock_redis)

        mock_request = MagicMock(spec=Request)
        mock_request.url = URL("/api/v1/test")
        mock_request.state = MagicMock()
        mock_request.state.user = MagicMock()
        mock_request.state.user.id = "user123"
        mock_request.state.user.subscription_tier = "pro"  # Pro tier

        async def mock_call_next(_request):
            return Response(content=b'{"status": "ok"}', status_code=200)

        response = await middleware.dispatch(mock_request, mock_call_next)

        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "1000"  # Pro tier


class TestRateLimitRecovery:
    """Tests for rate limit recovery after window reset."""

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        return AsyncMock()

    def _create_pipeline_mock(self, count: int) -> MagicMock:
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
    async def test_rate_limit_recovers_after_window(self, mock_redis: AsyncMock):
        """Rate limit should recover after window expires."""
        rate_limiter = SlidingWindowRateLimiter(redis=mock_redis)

        # First request: at limit
        pipeline = self._create_pipeline_mock(count=100)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        allowed, remaining, _reset = await rate_limiter.check_rate_limit(key="user:123", limit=100)
        assert allowed is False

        # Simulate window reset (count back to 0)
        pipeline = self._create_pipeline_mock(count=0)
        mock_redis.pipeline = MagicMock(return_value=pipeline)

        allowed, remaining, _reset = await rate_limiter.check_rate_limit(key="user:123", limit=100)
        assert allowed is True
        assert remaining == 99  # 100 - 0 - 1 (current request)
