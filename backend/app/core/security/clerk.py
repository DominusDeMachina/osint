"""Clerk JWT validation module.

Implements JWT validation using Clerk's JWKS endpoint for RS256 signature verification.
Caches JWKS keys with TTL to minimize external requests.
"""

import threading
import time
from dataclasses import dataclass

import httpx
from jose import JWTError, jwt

from app.core.config import settings


@dataclass
class ClerkTokenClaims:
    """Parsed claims from a validated Clerk JWT."""

    sub: str  # Clerk user ID (e.g., "user_2abc...")
    email: str | None = None
    session_id: str | None = None  # "sid" claim
    org_id: str | None = None  # Clerk organization ID (optional)
    org_role: str | None = None  # Role in organization (optional)
    metadata: dict | None = None  # Custom metadata


class JWKSCache:
    """Thread-safe cache for JWKS keys with TTL."""

    def __init__(self, ttl_seconds: int = 3600):
        self._keys: dict | None = None
        self._fetched_at: float = 0
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def get_keys(self, issuer: str) -> dict:
        """Get JWKS keys, fetching from Clerk if cache expired.

        Thread-safe: uses lock to prevent concurrent refresh race conditions.
        """
        now = time.time()

        # Check if refresh needed (without lock for performance)
        if self._keys is not None and (now - self._fetched_at) <= self._ttl:
            return self._keys

        # Acquire lock for refresh
        with self._lock:
            # Double-check after acquiring lock (another thread may have refreshed)
            if self._keys is None or (now - self._fetched_at) > self._ttl:
                self._keys = self._fetch_jwks(issuer)
                self._fetched_at = time.time()

            return self._keys

    def _fetch_jwks(self, issuer: str) -> dict:
        """Fetch JWKS from Clerk's well-known endpoint."""
        jwks_url = f"{issuer}/.well-known/jwks.json"

        try:
            response = httpx.get(jwks_url, timeout=10.0)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise ValueError(f"Failed to fetch JWKS from {jwks_url}: {e}") from e

    def clear(self) -> None:
        """Clear the cache (useful for testing)."""
        with self._lock:
            self._keys = None
            self._fetched_at = 0


# Global JWKS cache instance (1 hour TTL)
_jwks_cache = JWKSCache(ttl_seconds=3600)


def get_jwks_cache() -> JWKSCache:
    """Get the global JWKS cache instance."""
    return _jwks_cache


async def validate_clerk_token(token: str) -> ClerkTokenClaims:
    """Validate a Clerk JWT and return parsed claims.

    Args:
        token: The JWT string from Authorization header (without "Bearer " prefix)

    Returns:
        ClerkTokenClaims with validated user information

    Raises:
        ValueError: If token is invalid, expired, or signature verification fails
    """
    issuer = settings.clerk_issuer
    if not issuer:
        raise ValueError("CLERK_ISSUER not configured. Set the CLERK_ISSUER environment variable.")

    try:
        # Get the key ID from token header (without verification)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise ValueError("Token missing 'kid' header")

        # Get JWKS keys (cached)
        jwks = _jwks_cache.get_keys(issuer)

        # Find matching key by kid
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break

        if key is None:
            # Key not found - might be rotated, clear cache and retry once
            _jwks_cache.clear()
            jwks = _jwks_cache.get_keys(issuer)

            for k in jwks.get("keys", []):
                if k.get("kid") == kid:
                    key = k
                    break

            if key is None:
                raise ValueError(f"No matching key found for kid: {kid}")

        # Verify and decode the token
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            options={
                "verify_aud": False,  # Clerk tokens may not have audience
                "verify_exp": True,
                "verify_iss": True,
            },
        )

        # Extract claims
        return ClerkTokenClaims(
            sub=claims["sub"],
            email=claims.get("email"),
            session_id=claims.get("sid"),
            org_id=claims.get("org_id"),
            org_role=claims.get("org_role"),
            metadata=claims.get("metadata"),
        )

    except JWTError as e:
        raise ValueError(f"Invalid token: {e}") from e
    except KeyError as e:
        raise ValueError(f"Missing required claim: {e}") from e
