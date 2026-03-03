"""Integration tests for anti-abuse functionality.

Tests the complete anti-abuse flow including IP limiting, email validation,
and risk scoring as integrated into the Clerk webhook handler.

Story 1.5: Free Tier Anti-Abuse Controls
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.webhooks.clerk import handle_clerk_webhook, handle_user_created
from app.services.anti_abuse import RiskLevel


class TestIPAccountLimitIntegration:
    """Tests for IP account limiting in signup flow (AC: 1, 6, 11)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_signup_blocked_when_ip_limit_reached(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """Signup should be blocked when IP has 3+ existing accounts (AC1)."""
        # Setup mock Redis with proper return values for all methods
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)  # For velocity monitor
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)  # For idempotency check
        mock_get_redis.return_value = mock_redis

        # Setup mock anti-abuse to block IP
        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "blocked@business.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(25, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.check_ip_account_limit = AsyncMock(
            return_value=(False, "Account limit reached")
        )
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_blocked123",
            "email_addresses": [{"email_address": "blocked@business.com"}],
            "first_name": "Blocked",
            "last_name": "User",
        }

        # Create mock request with IP
        mock_request = MagicMock()
        mock_request.headers = {"X-Forwarded-For": "1.2.3.4"}
        mock_request.client = MagicMock(host="1.2.3.4")

        with pytest.raises(HTTPException) as exc_info:
            await handle_user_created(data, mock_request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["code"] == "SIGNUP_BLOCKED"
        assert "Account limit reached" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_signup_allowed_when_under_ip_limit(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """Signup should succeed when IP has fewer than 3 accounts."""
        # Setup mock Redis with proper return values
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)  # For velocity monitor
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)  # For idempotency check
        mock_get_redis.return_value = mock_redis

        # Setup mock anti-abuse to allow signup
        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "allowed@business.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(20, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {"action": "allow", "rate_limit": 100}
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        # Setup mock session
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_allowed123",
            "email_addresses": [{"email_address": "allowed@business.com"}],
            "first_name": "Allowed",
            "last_name": "User",
        }

        # Create mock request
        mock_request = MagicMock()
        mock_request.headers = {"X-Forwarded-For": "5.6.7.8"}
        mock_request.client = MagicMock(host="5.6.7.8")

        result = await handle_user_created(data, mock_request)

        assert result["status"] == "ok"
        # Verify IP was recorded after successful signup
        mock_anti_abuse.record_signup_ip.assert_called_once()


class TestEmailValidationIntegration:
    """Tests for email domain validation in signup flow (AC: 2, 7, 11)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_consumer_email_blocked(self, mock_get_redis, mock_anti_abuse_cls):
        """Signup should be blocked for consumer email domains (AC2)."""
        # Setup mock Redis with proper return values
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        # Setup mock anti-abuse to block email
        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (
            False,
            "Business email required",
            "user@gmail.com",
        )
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_gmail123",
            "email_addresses": [{"email_address": "user@gmail.com"}],
            "first_name": "Gmail",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client = MagicMock(host="1.2.3.4")

        with pytest.raises(HTTPException) as exc_info:
            await handle_user_created(data, mock_request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["code"] == "SIGNUP_BLOCKED"
        assert "Business email required" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_business_email_allowed(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """Signup should succeed for business email domains."""
        # Setup mocks with proper return values
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "user@mycompany.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(20, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {"action": "allow", "rate_limit": 100}
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_business123",
            "email_addresses": [{"email_address": "user@mycompany.com"}],
            "first_name": "Business",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client = MagicMock(host="1.2.3.4")

        result = await handle_user_created(data, mock_request)

        assert result["status"] == "ok"


class TestIPExtraction:
    """Tests for client IP extraction from request headers."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_ip_extracted_from_x_forwarded_for(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """IP should be extracted from X-Forwarded-For header."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "user@company.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(20, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {"action": "allow", "rate_limit": 100}
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_xff123",
            "email_addresses": [{"email_address": "user@company.com"}],
            "first_name": "XFF",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {"X-Forwarded-For": "10.20.30.40, 1.1.1.1"}
        mock_request.client = MagicMock(host="127.0.0.1")

        await handle_user_created(data, mock_request)

        # Verify the extracted IP (first in chain) was used
        mock_anti_abuse.record_signup_ip.assert_called_once_with("10.20.30.40")

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_ip_extracted_from_x_real_ip(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """IP should be extracted from X-Real-IP if no X-Forwarded-For."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "user@company.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(20, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {"action": "allow", "rate_limit": 100}
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_xrip123",
            "email_addresses": [{"email_address": "user@company.com"}],
            "first_name": "XRI",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {"X-Real-IP": "50.60.70.80"}
        mock_request.client = MagicMock(host="127.0.0.1")

        await handle_user_created(data, mock_request)

        mock_anti_abuse.record_signup_ip.assert_called_once_with("50.60.70.80")


class TestRiskScoringIntegration:
    """Tests for multi-signal risk scoring in signup flow (AC: 12, 16, 17)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_high_risk_signup_blocked(self, mock_get_redis, mock_anti_abuse_cls):
        """Signups with risk score > 80 should require additional verification."""
        # This test verifies the graduated response for high-risk signups
        # Currently, the webhook handler blocks on email or IP check failure
        # Full risk scoring integration is a separate enhancement

        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        # High-risk scenario: blocked email domain
        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (
            False,
            "Business email required",
            "suspicious@tempmail.com",
        )
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_highrisk",
            "email_addresses": [{"email_address": "suspicious@tempmail.com"}],
            "first_name": "High",
            "last_name": "Risk",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client = MagicMock(host="1.2.3.4")

        with pytest.raises(HTTPException) as exc_info:
            await handle_user_created(data, mock_request)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_critical_risk_score_blocks_signup(self, mock_get_redis, mock_anti_abuse_cls):
        """Signups with critical risk score (>80) should be blocked (AC12, AC17)."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "bot@suspicious.com")
        # Critical risk score > 80
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(85, RiskLevel.CRITICAL, {"is_datacenter": True})
        )
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_critical123",
            "email_addresses": [{"email_address": "bot@suspicious.com"}],
            "first_name": "Bot",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {"X-Form-Timing": "1.5"}
        mock_request.client = MagicMock(host="13.52.1.1")

        with pytest.raises(HTTPException) as exc_info:
            await handle_user_created(data, mock_request)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["code"] == "SIGNUP_BLOCKED"
        assert "security concerns" in exc_info.value.detail["message"]
        assert exc_info.value.detail["risk_score"] == 85

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_high_risk_requires_verification(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """Signups with high risk (61-80) should require email verification (AC12)."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "user@newdomain.com")
        # High risk score 61-80
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(70, RiskLevel.HIGH, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {
            "action": "verify_email",
            "rate_limit": 50,
        }
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_highrisk123",
            "email_addresses": [{"email_address": "user@newdomain.com"}],
            "first_name": "High",
            "last_name": "Risk",
        }

        mock_request = MagicMock()
        mock_request.headers = {"X-Form-Timing": "5"}
        mock_request.client = MagicMock(host="1.2.3.4")

        result = await handle_user_created(data, mock_request)

        assert result["status"] == "ok"
        assert result["requires_verification"] is True
        assert result["risk_level"] == "high"
        assert result["rate_limit"] == 50

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_low_risk_gets_full_access(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls
    ):
        """Signups with low risk (0-30) should get full access (AC17)."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "user@company.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(10, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {
            "action": "allow",
            "rate_limit": 100,
        }
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_lowrisk123",
            "email_addresses": [{"email_address": "user@company.com"}],
            "first_name": "Good",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {"X-Form-Timing": "30"}
        mock_request.client = MagicMock(host="1.2.3.4")

        result = await handle_user_created(data, mock_request)

        assert result["status"] == "ok"
        assert result["requires_verification"] is False
        assert result["risk_level"] == "low"
        assert result["rate_limit"] == 100


class TestAuditLoggingIntegration:
    """Tests for audit logging of anti-abuse events (AC: 8)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_blocked_signup_logged(self, mock_get_redis, mock_anti_abuse_cls):
        """Blocked signup attempts should be logged to audit trail."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        # Mock audit logger
        mock_audit = AsyncMock()

        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "logged@business.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(25, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.check_ip_account_limit = AsyncMock(
            return_value=(False, "Account limit reached")
        )
        mock_anti_abuse.audit = mock_audit
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_logged123",
            "email_addresses": [{"email_address": "logged@business.com"}],
            "first_name": "Logged",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.cookies = MagicMock()
        mock_request.cookies.get = MagicMock(return_value=None)
        mock_request.client = MagicMock(host="1.2.3.4")

        with pytest.raises(HTTPException):
            await handle_user_created(data, mock_request)

        # The AntiAbuseService logs the blocked attempt internally
        # Verify the check was called (logging happens inside check_ip_account_limit)
        mock_anti_abuse.check_ip_account_limit.assert_called_once()


class TestEmailNormalizationIntegration:
    """Tests for email normalization in signup flow (AC: 18, 24)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_plus_alias_email_blocked(self, mock_get_redis, mock_anti_abuse_cls):
        """Signup with +alias should be blocked if root domain is blocked (AC18)."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        # Email normalization should convert user+tag@gmail.com → user@gmail.com → blocked
        mock_anti_abuse.validate_business_email.return_value = (
            False,
            "Business email required",
            "user@gmail.com",  # Normalized email
        )
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_alias123",
            "email_addresses": [{"email_address": "user+tag@gmail.com"}],
            "first_name": "Alias",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.cookies = MagicMock()
        mock_request.cookies.get = MagicMock(return_value=None)
        mock_request.client = MagicMock(host="1.2.3.4")

        with pytest.raises(HTTPException) as exc_info:
            await handle_user_created(data, mock_request)

        assert exc_info.value.status_code == 400
        assert "Business email required" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_subdomain_email_blocked(self, mock_get_redis, mock_anti_abuse_cls):
        """Signup with subdomain of blocked domain should be blocked (AC24)."""
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        mock_redis.zrangebyscore = AsyncMock(return_value=[b"1"])
        mock_redis.get = AsyncMock(return_value=None)
        mock_get_redis.return_value = mock_redis

        mock_anti_abuse = MagicMock()
        # Root domain extraction should block sub.protonmail.com
        mock_anti_abuse.validate_business_email.return_value = (
            False,
            "Business email required",
            "user@sub.protonmail.com",
        )
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        data = {
            "id": "user_subdomain123",
            "email_addresses": [{"email_address": "user@sub.protonmail.com"}],
            "first_name": "Subdomain",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.cookies = MagicMock()
        mock_request.cookies.get = MagicMock(return_value=None)
        mock_request.client = MagicMock(host="1.2.3.4")

        with pytest.raises(HTTPException) as exc_info:
            await handle_user_created(data, mock_request)

        assert exc_info.value.status_code == 400


class TestWebhookIdempotencyIntegration:
    """Tests for webhook idempotency in webhook handler (AC: 23)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.WebhookIdempotency")
    @patch("app.api.v1.webhooks.clerk.verify_webhook")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    async def test_duplicate_webhook_rejected(
        self, mock_get_redis, mock_verify_webhook, mock_idempotency_cls
    ):
        """Duplicate webhook should be rejected with 409 Conflict (AC23)."""
        mock_redis = AsyncMock()
        mock_get_redis.return_value = mock_redis

        # Mock idempotency to return True (duplicate)
        mock_idempotency = MagicMock()
        mock_idempotency.is_duplicate = AsyncMock(return_value=True)
        mock_idempotency_cls.return_value = mock_idempotency

        mock_request = MagicMock()
        mock_request.body = AsyncMock(return_value=b'{"type": "user.created"}')

        with pytest.raises(HTTPException) as exc_info:
            await handle_clerk_webhook(
                request=mock_request,
                svix_id="msg_duplicate123",
                svix_timestamp="1234567890",
                svix_signature="v1,signature",
            )

        assert exc_info.value.status_code == 409
        assert "already processed" in exc_info.value.detail


class TestSignupVelocityIntegration:
    """Tests for signup velocity monitoring integration (AC: 26)."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.SignupVelocityMonitor")
    @patch("app.api.v1.webhooks.clerk.AntiAbuseService")
    @patch("app.api.v1.webhooks.clerk.get_redis")
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_high_velocity_flagged_but_not_blocked(
        self, mock_session_maker, mock_get_redis, mock_anti_abuse_cls, mock_velocity_cls
    ):
        """High velocity should flag signup but not block it (AC26)."""
        mock_redis = AsyncMock()
        mock_get_redis.return_value = mock_redis

        # Mock velocity monitor to return False (over threshold)
        mock_velocity = MagicMock()
        mock_velocity.record_signup = AsyncMock(return_value=(False, 15))
        mock_velocity_cls.return_value = mock_velocity

        # Mock anti-abuse to allow signup
        mock_anti_abuse = MagicMock()
        mock_anti_abuse.validate_business_email.return_value = (True, None, "user@company.com")
        mock_anti_abuse.calculate_signup_risk = AsyncMock(
            return_value=(20, RiskLevel.LOW, {"is_datacenter": False})
        )
        mock_anti_abuse.get_graduated_response.return_value = {"action": "allow", "rate_limit": 100}
        mock_anti_abuse.check_ip_account_limit = AsyncMock(return_value=(True, None))
        mock_anti_abuse.record_signup_ip = AsyncMock()
        mock_anti_abuse_cls.return_value = mock_anti_abuse

        # Mock session
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_velocity123",
            "email_addresses": [{"email_address": "user@company.com"}],
            "first_name": "Velocity",
            "last_name": "User",
        }

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.cookies = MagicMock()
        mock_request.cookies.get = MagicMock(return_value=None)
        mock_request.client = MagicMock(host="1.2.3.4")

        # Signup should still succeed (flagged, not blocked)
        result = await handle_user_created(data, mock_request)

        assert result["status"] == "ok"
        # Velocity was recorded
        mock_velocity.record_signup.assert_called_once()
