"""Unit tests for Clerk JWT validation."""

from unittest.mock import MagicMock, patch

import pytest
from jose import JWTError

from app.core.security.clerk import (
    ClerkTokenClaims,
    JWKSCache,
    get_jwks_cache,
    validate_clerk_token,
)


TEST_JWK = {
    "kty": "RSA",
    "kid": "test-key-id",
    "use": "sig",
    "alg": "RS256",
    "n": "test-modulus",
    "e": "AQAB",
}

TEST_JWKS = {"keys": [TEST_JWK]}
TEST_ISSUER = "https://test.clerk.accounts.dev"
TEST_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0.test.signature"


class TestJWKSCache:
    """Tests for JWKS caching."""

    def test_cache_initialization(self):
        """Test cache initializes empty."""
        cache = JWKSCache(ttl_seconds=3600)
        assert cache._keys is None
        assert cache._fetched_at == 0

    def test_cache_clear(self):
        """Test cache clearing."""
        cache = JWKSCache()
        cache._keys = {"test": "data"}
        cache._fetched_at = 1000
        cache.clear()
        assert cache._keys is None
        assert cache._fetched_at == 0

    @patch("app.core.security.clerk.httpx.get")
    def test_cache_fetches_jwks(self, mock_get):
        """Test cache fetches JWKS on first access."""
        mock_response = MagicMock()
        mock_response.json.return_value = TEST_JWKS
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        cache = JWKSCache()
        keys = cache.get_keys(TEST_ISSUER)

        assert keys == TEST_JWKS
        mock_get.assert_called_once_with(
            f"{TEST_ISSUER}/.well-known/jwks.json",
            timeout=10.0,
        )

    @patch("app.core.security.clerk.httpx.get")
    def test_cache_returns_cached_keys(self, mock_get):
        """Test cache returns cached keys without fetching."""
        mock_response = MagicMock()
        mock_response.json.return_value = TEST_JWKS
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        cache = JWKSCache(ttl_seconds=3600)

        # First call fetches
        cache.get_keys(TEST_ISSUER)
        # Second call uses cache
        cache.get_keys(TEST_ISSUER)

        # Should only fetch once
        assert mock_get.call_count == 1


class TestValidateClerkToken:
    """Tests for JWT validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        # Clear the global JWKS cache before each test
        get_jwks_cache().clear()

    @pytest.mark.asyncio
    @patch("app.core.security.clerk.jwt.decode")
    @patch("app.core.security.clerk.jwt.get_unverified_header")
    @patch("app.core.security.clerk.settings")
    @patch("app.core.security.clerk._jwks_cache")
    async def test_validate_valid_token(
        self, mock_cache, mock_settings, mock_get_header, mock_decode
    ):
        """Test valid JWT is accepted."""
        mock_settings.clerk_issuer = TEST_ISSUER
        mock_cache.get_keys.return_value = TEST_JWKS
        mock_cache.clear = MagicMock()
        mock_get_header.return_value = {"kid": "test-key-id", "alg": "RS256"}
        mock_decode.return_value = {
            "sub": "user_abc123",
            "email": "test@example.com",
        }

        claims = await validate_clerk_token(TEST_TOKEN)

        assert isinstance(claims, ClerkTokenClaims)
        assert claims.sub == "user_abc123"
        assert claims.email == "test@example.com"

    @pytest.mark.asyncio
    @patch("app.core.security.clerk.jwt.decode")
    @patch("app.core.security.clerk.jwt.get_unverified_header")
    @patch("app.core.security.clerk.settings")
    @patch("app.core.security.clerk._jwks_cache")
    async def test_reject_expired_token(
        self, mock_cache, mock_settings, mock_get_header, mock_decode
    ):
        """Test expired JWT is rejected."""
        mock_settings.clerk_issuer = TEST_ISSUER
        mock_cache.get_keys.return_value = TEST_JWKS
        mock_cache.clear = MagicMock()
        mock_get_header.return_value = {"kid": "test-key-id", "alg": "RS256"}
        mock_decode.side_effect = JWTError("Signature has expired")

        with pytest.raises(ValueError, match="Invalid token"):
            await validate_clerk_token(TEST_TOKEN)

    @pytest.mark.asyncio
    @patch("app.core.security.clerk.jwt.decode")
    @patch("app.core.security.clerk.jwt.get_unverified_header")
    @patch("app.core.security.clerk.settings")
    @patch("app.core.security.clerk._jwks_cache")
    async def test_reject_invalid_signature(
        self, mock_cache, mock_settings, mock_get_header, mock_decode
    ):
        """Test JWT with wrong signature is rejected."""
        mock_settings.clerk_issuer = TEST_ISSUER
        mock_cache.get_keys.return_value = TEST_JWKS
        mock_cache.clear = MagicMock()
        mock_get_header.return_value = {"kid": "test-key-id", "alg": "RS256"}
        mock_decode.side_effect = JWTError("Signature verification failed")

        with pytest.raises(ValueError, match="Invalid token"):
            await validate_clerk_token(TEST_TOKEN)

    @pytest.mark.asyncio
    @patch("app.core.security.clerk.settings")
    async def test_reject_missing_issuer_config(self, mock_settings):
        """Test validation fails when CLERK_ISSUER not configured."""
        mock_settings.clerk_issuer = ""

        with pytest.raises(ValueError, match="CLERK_ISSUER not configured"):
            await validate_clerk_token(TEST_TOKEN)

    @pytest.mark.asyncio
    @patch("app.core.security.clerk.jwt.get_unverified_header")
    @patch("app.core.security.clerk.settings")
    @patch("app.core.security.clerk._jwks_cache")
    async def test_reject_unknown_key_id(self, mock_cache, mock_settings, mock_get_header):
        """Test JWT with unknown key ID is rejected."""
        mock_settings.clerk_issuer = TEST_ISSUER
        mock_cache.get_keys.return_value = TEST_JWKS
        mock_cache.clear = MagicMock()
        mock_get_header.return_value = {"kid": "unknown-key-id", "alg": "RS256"}

        with pytest.raises(ValueError, match="No matching key found"):
            await validate_clerk_token(TEST_TOKEN)


class TestAuthorizationHeader:
    """Tests for Authorization header handling."""

    def test_missing_authorization_header(self, client):
        """Test request without Authorization header returns 401."""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert "Missing authentication" in response.json()["detail"]

    def test_invalid_authorization_format(self, client):
        """Test request with invalid Authorization format returns 401."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "InvalidFormat token123"},
        )
        assert response.status_code == 401

    def test_empty_bearer_token(self, client):
        """Test request with empty Bearer token returns 401."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer "},
        )
        assert response.status_code == 401
