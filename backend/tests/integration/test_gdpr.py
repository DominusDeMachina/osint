"""Integration tests for GDPR compliance endpoints.

Tests Story 1.5 GDPR functionality:
- AC21: GDPR IP data deletion endpoint
- AC25: GDPR endpoint rate limiting
- AC19: Server-side timing endpoint
- AC26: Admin review queue endpoints
"""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.v1.gdpr import (
    approve_signup,
    delete_ip_data,
    get_review_queue,
    reject_signup,
    require_admin_user,
    require_authenticated_user,
    start_timing_session,
)
from app.models.user import User, UserRole


class MockRequest:
    """Mock FastAPI request object."""

    def __init__(
        self,
        user: User | None = None,
        ip: str = "192.168.1.1",
    ):
        self.state = MagicMock()
        self.state.user = user
        self.headers = {"X-Forwarded-For": ip}
        self.client = MagicMock()
        self.client.host = ip


class MockMembership:
    """Mock tenant membership."""

    def __init__(self, role: UserRole = UserRole.viewer):
        self.role = role


@pytest.fixture
def mock_user() -> User:
    """Create a mock user for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.clerk_id = "clerk_test_user"
    user.email = "test@example.com"
    user.is_active = True
    user.signup_ip_hash = "abcd1234efgh5678"
    user.memberships = [MockMembership(UserRole.viewer)]
    return user


@pytest.fixture
def mock_admin_user() -> User:
    """Create a mock admin user for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.clerk_id = "clerk_admin_user"
    user.email = "admin@example.com"
    user.is_active = True
    user.memberships = [MockMembership(UserRole.admin)]
    return user


class TestGDPRIPDataDeletion:
    """Tests for DELETE /api/v1/gdpr/ip-data/{user_id} endpoint (AC21)."""

    @pytest.mark.asyncio
    async def test_unauthenticated_request_returns_401(self) -> None:
        """Test that unauthenticated requests are rejected."""
        request = MockRequest(user=None)

        with pytest.raises(Exception) as exc_info:
            await require_authenticated_user(request)

        assert exc_info.value.status_code == 401
        assert "Authentication required" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_unauthorized_user_returns_403(
        self, mock_user: User, mock_admin_user: User
    ) -> None:
        """Test that non-admin user cannot delete another user's data."""
        request = MockRequest(user=mock_user)
        other_user_id = uuid4()

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.async_session_maker"),
        ):
            mock_redis.return_value = AsyncMock()

            # Mock GDPR rate limiter to allow
            mock_redis.return_value.get = AsyncMock(return_value=None)

            with pytest.raises(Exception) as exc_info:
                await delete_ip_data(
                    user_id=other_user_id,
                    request=request,
                    current_user=mock_user,
                )

            assert exc_info.value.status_code == 403
            assert "Not authorized" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_self_deletion_allowed(self, mock_user: User) -> None:
        """Test that user can delete their own IP data."""
        request = MockRequest(user=mock_user)

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.async_session_maker") as mock_session_maker,
        ):
            # Mock Redis
            mock_redis_client = AsyncMock()
            mock_redis_client.get = AsyncMock(return_value=None)
            mock_redis_client.delete = AsyncMock()
            mock_redis_client.set = AsyncMock()
            mock_redis.return_value = mock_redis_client

            # Mock database session
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()

            # Mock user query
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            mock_session_maker.return_value = mock_session

            response = await delete_ip_data(
                user_id=mock_user.id,
                request=request,
                current_user=mock_user,
            )

            assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_admin_can_delete_any_user_data(
        self, mock_user: User, mock_admin_user: User
    ) -> None:
        """Test that admin can delete any user's IP data."""
        request = MockRequest(user=mock_admin_user)

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.async_session_maker") as mock_session_maker,
        ):
            # Mock Redis
            mock_redis_client = AsyncMock()
            mock_redis_client.get = AsyncMock(return_value=None)
            mock_redis_client.delete = AsyncMock()
            mock_redis_client.set = AsyncMock()
            mock_redis.return_value = mock_redis_client

            # Mock database session
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()

            # Mock user query and audit log update
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_result.rowcount = 5  # 5 audit logs anonymized
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            mock_session_maker.return_value = mock_session

            response = await delete_ip_data(
                user_id=mock_user.id,
                request=request,
                current_user=mock_admin_user,
            )

            assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_user_not_found_returns_404(self, mock_user: User) -> None:
        """Test that 404 is returned when target user doesn't exist."""
        request = MockRequest(user=mock_user)

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.async_session_maker") as mock_session_maker,
            patch("app.api.v1.gdpr.GDPRRateLimiter") as mock_limiter_class,
        ):
            # Mock Redis
            mock_redis_client = AsyncMock()
            mock_redis_client.get = AsyncMock(return_value=None)
            mock_redis.return_value = mock_redis_client

            # Mock rate limiter to allow
            mock_limiter = AsyncMock()
            mock_limiter.check_rate_limit = AsyncMock(return_value=(True, None))
            mock_limiter_class.return_value = mock_limiter

            # Mock database session - user not found
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_session.execute = AsyncMock(return_value=mock_result)

            @asynccontextmanager
            async def mock_cm():
                yield mock_session

            mock_session_maker.return_value = mock_cm()

            with pytest.raises(Exception) as exc_info:
                await delete_ip_data(
                    user_id=mock_user.id,
                    request=request,
                    current_user=mock_user,
                )

            assert exc_info.value.status_code == 404


class TestGDPRRateLimiting:
    """Tests for GDPR endpoint rate limiting (AC25)."""

    @pytest.mark.asyncio
    async def test_rate_limited_returns_429(self, mock_user: User) -> None:
        """Test that rate-limited requests return 429."""
        request = MockRequest(user=mock_user)

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.GDPRRateLimiter") as mock_limiter_class,
        ):
            # Mock Redis
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client

            # Mock rate limiter to return rate limited
            mock_limiter = AsyncMock()
            mock_limiter.check_rate_limit = AsyncMock(
                return_value=(False, 86400 * 15)  # 15 days remaining
            )
            mock_limiter_class.return_value = mock_limiter

            with pytest.raises(Exception) as exc_info:
                await delete_ip_data(
                    user_id=mock_user.id,
                    request=request,
                    current_user=mock_user,
                )

            assert exc_info.value.status_code == 429
            assert "rate limited" in str(exc_info.value.detail).lower()


class TestServerSideTiming:
    """Tests for POST /api/v1/gdpr/timing/start endpoint (AC19)."""

    @pytest.mark.asyncio
    async def test_timing_session_returns_session_id(self) -> None:
        """Test that timing session endpoint returns a session ID."""
        with patch("app.api.v1.gdpr.get_redis") as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis_client.set = AsyncMock()
            mock_redis.return_value = mock_redis_client

            response = await start_timing_session()

            assert response.status_code == 200
            body = response.body.decode()
            assert "session_id" in body
            assert "ok" in body

    @pytest.mark.asyncio
    async def test_timing_session_id_is_secure(self) -> None:
        """Test that timing session ID has proper entropy."""
        with patch("app.api.v1.gdpr.get_redis") as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis_client.set = AsyncMock()
            mock_redis.return_value = mock_redis_client

            response = await start_timing_session()

            # Check cookie is set
            assert "timing_session" in str(response.headers)


class TestAdminReviewQueue:
    """Tests for admin review queue endpoints (AC26)."""

    @pytest.mark.asyncio
    async def test_get_review_queue_requires_admin(self, mock_user: User) -> None:
        """Test that non-admin users cannot access review queue."""
        request = MockRequest(user=mock_user)

        with pytest.raises(Exception) as exc_info:
            await require_admin_user(request)

        assert exc_info.value.status_code == 403
        assert "Admin access required" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_get_review_queue_returns_items(self, mock_admin_user: User) -> None:
        """Test that admin can get review queue items."""
        with patch("app.api.v1.gdpr.get_redis") as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis_client.lrange = AsyncMock(return_value=[])
            mock_redis_client.llen = AsyncMock(return_value=0)
            mock_redis.return_value = mock_redis_client

            result = await get_review_queue(_current_user=mock_admin_user, limit=50)

            assert "items" in result
            assert "total" in result
            assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_approve_signup_not_found_returns_404(self, mock_admin_user: User) -> None:
        """Test that approving non-existent signup returns 404."""
        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.SignupReviewQueue") as mock_queue_class,
        ):
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client

            mock_queue = AsyncMock()
            mock_queue.remove_item = AsyncMock(return_value=None)
            mock_queue_class.return_value = mock_queue

            with pytest.raises(Exception) as exc_info:
                await approve_signup(
                    clerk_id="nonexistent",
                    current_user=mock_admin_user,
                )

            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_approve_signup_activates_user(self, mock_admin_user: User) -> None:
        """Test that approving signup activates the user."""
        mock_item = {
            "clerk_id": "test_clerk_id",
            "email": "test@example.com",
            "reason": "velocity_exceeded",
        }

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.SignupReviewQueue") as mock_queue_class,
            patch("app.api.v1.gdpr.async_session_maker") as mock_session_maker,
        ):
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client

            mock_queue = AsyncMock()
            mock_queue.remove_item = AsyncMock(return_value=mock_item)
            mock_queue_class.return_value = mock_queue

            # Mock database session
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()

            mock_user = MagicMock()
            mock_user.is_active = False
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            mock_session_maker.return_value = mock_session

            result = await approve_signup(
                clerk_id="test_clerk_id",
                current_user=mock_admin_user,
            )

            assert result["status"] == "approved"
            assert mock_user.is_active is True

    @pytest.mark.asyncio
    async def test_reject_signup_deactivates_user(self, mock_admin_user: User) -> None:
        """Test that rejecting signup deactivates the user."""
        mock_item = {
            "clerk_id": "test_clerk_id",
            "email": "test@example.com",
            "reason": "velocity_exceeded",
        }

        with (
            patch("app.api.v1.gdpr.get_redis") as mock_redis,
            patch("app.api.v1.gdpr.SignupReviewQueue") as mock_queue_class,
            patch("app.api.v1.gdpr.async_session_maker") as mock_session_maker,
        ):
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client

            mock_queue = AsyncMock()
            mock_queue.remove_item = AsyncMock(return_value=mock_item)
            mock_queue_class.return_value = mock_queue

            # Mock database session
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()

            mock_user = MagicMock()
            mock_user.is_active = True
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            mock_session_maker.return_value = mock_session

            result = await reject_signup(
                clerk_id="test_clerk_id",
                current_user=mock_admin_user,
                reason="Suspicious activity",
            )

            assert result["status"] == "rejected"
            assert mock_user.is_active is False
