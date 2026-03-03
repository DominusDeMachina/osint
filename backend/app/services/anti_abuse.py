"""Anti-abuse service for preventing free tier abuse.

Implements Story 1.5: Free Tier Anti-Abuse Controls.

Provides:
- IP-based account limiting (max 3 accounts per IP)
- Business email domain validation (block consumer domains)
- Email normalization to prevent bypass attacks (AC18)
- Root domain extraction using Public Suffix List (AC24)
- Multi-signal abuse risk scoring
- Server-side form timing (AC19)
- Webhook idempotency tracking (AC23)
- Signup velocity monitoring (AC26)
- GDPR compliance utilities (AC21, AC25)

All IP addresses are hashed before storage for GDPR compliance.
"""

import hashlib
import ipaddress
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar, Protocol


try:
    import tldextract

    HAS_TLDEXTRACT = True
except ImportError:
    import logging

    logging.getLogger(__name__).warning(
        "tldextract not installed. Root domain extraction will use fallback "
        "that may not handle multi-part TLDs (.co.uk, .com.au) correctly. "
        "Install with: pip install tldextract"
    )
    HAS_TLDEXTRACT = False

from app.core.config import settings


if TYPE_CHECKING:
    from redis.asyncio import Redis


# Known disposable email domains (AC2.7 - extend for production)
# These are temporary email services that should be blocked
DISPOSABLE_EMAIL_DOMAINS: set[str] = {
    "mailinator.com",
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "throwaway.email",
    "fakeinbox.com",
    "trashmail.com",
    "yopmail.com",
    "getnada.com",
    "temp-mail.org",
    "dispostable.com",
    "mailnesia.com",
    "sharklasers.com",
    "guerrillamail.info",
    "grr.la",
    "guerrillamail.biz",
    "guerrillamail.de",
    "guerrillamail.net",
    "guerrillamail.org",
    "spam4.me",
    "maildrop.cc",
    "mailsac.com",
    "mytrashmail.com",
    "mt2014.com",
    "thankyou2010.com",
    "trash-mail.at",
    "trashmail.net",
    "wegwerfemail.de",
    "emailondeck.com",
    "tempr.email",
    "discard.email",
    "discardmail.com",
    "spamgourmet.com",
    "mintemail.com",
    "tempail.com",
    "emailfake.com",
    "mohmal.com",
}


# Known datacenter IP ranges (sample list - extend for production)
# These are common cloud provider ranges
DATACENTER_IP_RANGES: list[str] = [
    # AWS
    "3.0.0.0/8",
    "13.0.0.0/8",
    "15.0.0.0/8",
    "18.0.0.0/8",
    "52.0.0.0/8",
    "54.0.0.0/8",
    # GCP
    "35.192.0.0/12",
    "35.208.0.0/12",
    "35.224.0.0/12",
    "35.240.0.0/13",
    # Azure
    "40.64.0.0/10",
    "40.112.0.0/13",
    "104.40.0.0/13",
    # DigitalOcean
    "104.131.0.0/16",
    "138.68.0.0/16",
    "159.65.0.0/16",
    # Cloudflare
    "104.16.0.0/12",
    "172.64.0.0/13",
    "173.245.48.0/20",
]

# Pre-parsed networks for performance
_DATACENTER_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None


def _get_datacenter_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Lazily parse and cache datacenter IP networks."""
    global _DATACENTER_NETWORKS  # noqa: PLW0603
    if _DATACENTER_NETWORKS is None:
        _DATACENTER_NETWORKS = [ipaddress.ip_network(cidr) for cidr in DATACENTER_IP_RANGES]
    return _DATACENTER_NETWORKS


class RiskLevel(StrEnum):
    """Risk level classification for signup attempts.

    Implements AC16, AC17: Graduated response based on risk score.
    """

    LOW = "low"  # 0-30: Full access
    MEDIUM = "medium"  # 31-60: Reduced rate limits
    HIGH = "high"  # 61-80: Email verification required
    CRITICAL = "critical"  # 81-100: Blocked


@dataclass
class SignupContext:
    """Context for abuse risk assessment.

    Collects all signals needed to calculate risk score.
    """

    ip: str
    email: str
    form_timing_seconds: float | None = None
    device_fingerprint: str | None = None
    user_agent: str | None = None


@dataclass
class IPContext:
    """Enhanced IP intelligence for risk scoring.

    Implements AC13: Datacenter/VPN detection for stricter limits.
    """

    ip_hash: str
    account_count: int = 0
    is_datacenter: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    country: str | None = None


@dataclass
class EmailAnalysis:
    """Enhanced email intelligence for risk scoring.

    Implements AC14: Domain age check.
    """

    domain: str
    is_disposable: bool = False
    is_consumer: bool = False
    domain_age_days: int | None = None
    has_mx_record: bool = True
    local_part_entropy: float = 0.0


class AbuseRiskScore:
    """Multi-signal abuse detection combining IP, email, and behavioral signals.

    Implements AC12, AC16, AC17: Risk scoring and graduated response.

    Score breakdown (0-100):
    - IP signals: 0-30 (account count 0-15 + reputation 0-15)
    - Email signals: 0-30 (domain type 0-15 + domain age 0-15)
    - Behavioral signals: 0-40 (form timing 0-20 + fingerprint 0-20)
    """

    # Score thresholds for graduated response
    THRESHOLDS: ClassVar[dict[RiskLevel, int]] = {
        RiskLevel.LOW: 30,
        RiskLevel.MEDIUM: 60,
        RiskLevel.HIGH: 80,
        RiskLevel.CRITICAL: 100,
    }

    # Graduated response actions
    RESPONSES: ClassVar[dict[RiskLevel, dict[str, Any]]] = {
        RiskLevel.LOW: {"action": "allow", "rate_limit": 100},
        RiskLevel.MEDIUM: {"action": "allow", "rate_limit": 50},
        RiskLevel.HIGH: {"action": "verify_email", "rate_limit": 50},
        RiskLevel.CRITICAL: {"action": "block", "rate_limit": 0},
    }

    def calculate(
        self,
        context: SignupContext,
        ip_ctx: IPContext,
        email_analysis: EmailAnalysis,
    ) -> tuple[int, RiskLevel]:
        """Calculate combined risk score 0-100.

        Args:
            context: Signup context with behavioral data
            ip_ctx: IP intelligence data
            email_analysis: Email analysis data

        Returns:
            Tuple of (score: int, level: RiskLevel)
        """
        score = 0

        # IP signals (max 30 points)
        score += self._ip_account_score(ip_ctx.account_count)  # 0-15
        score += self._ip_reputation_score(ip_ctx)  # 0-15

        # Email signals (max 30 points)
        score += self._email_domain_score(email_analysis)  # 0-15
        score += self._email_age_score(email_analysis)  # 0-15

        # Behavioral signals (max 40 points)
        score += self._form_timing_score(context.form_timing_seconds)  # 0-20
        score += self._fingerprint_score(context.device_fingerprint)  # 0-20

        level = self._score_to_level(score)
        return score, level

    def _ip_account_score(self, count: int) -> int:
        """Score based on accounts from this IP.

        Args:
            count: Number of existing accounts from this IP

        Returns:
            Score 0-15
        """
        if count == 0:
            return 0
        if count == 1:
            return 5
        if count == 2:
            return 10
        return 15  # 3+ accounts

    def _ip_reputation_score(self, ip_ctx: IPContext) -> int:
        """Score based on IP type and reputation.

        Implements AC13: Stricter limits for datacenter/VPN IPs.

        Args:
            ip_ctx: IP context with reputation flags

        Returns:
            Score 0-15
        """
        score = 0
        if ip_ctx.is_datacenter:
            score += 10
        if ip_ctx.is_vpn:
            score += 5
        if ip_ctx.is_tor:
            score += 15
        return min(score, 15)

    def _email_domain_score(self, analysis: EmailAnalysis) -> int:
        """Score based on email domain characteristics.

        Args:
            analysis: Email analysis data

        Returns:
            Score 0-15
        """
        if analysis.is_disposable:
            return 15
        if not analysis.has_mx_record:
            return 15
        if analysis.is_consumer:
            return 10
        return 0

    def _email_age_score(self, analysis: EmailAnalysis) -> int:
        """Score based on domain age.

        Implements AC14: +risk for domains < 30 days old.

        Args:
            analysis: Email analysis data

        Returns:
            Score 0-15
        """
        if analysis.domain_age_days is None:
            return 5  # Unknown = suspicious
        if analysis.domain_age_days < 30:
            return 15  # Very new
        if analysis.domain_age_days < 90:
            return 10  # New
        if analysis.domain_age_days < 365:
            return 5  # Less than a year
        return 0

    def _form_timing_score(self, seconds: float | None) -> int:
        """Score based on form submission speed (bot detection).

        Implements AC15: Flag signups with timing < 3 seconds.

        Args:
            seconds: Form submission time in seconds

        Returns:
            Score 0-20
        """
        if seconds is None:
            return 10  # Unknown = suspicious
        if seconds < 3:
            return 20  # Too fast = bot
        if seconds < 10:
            return 10  # Suspiciously fast
        return 0

    def _fingerprint_score(self, _fingerprint: str | None) -> int:
        """Score based on device fingerprint (POST-MVP).

        Args:
            _fingerprint: Device fingerprint hash (unused - placeholder for future)

        Returns:
            Score 0-20 (currently always 0 - placeholder)
        """
        # Placeholder for future implementation
        return 0

    def _score_to_level(self, score: int) -> RiskLevel:
        """Convert score to risk level.

        Args:
            score: Combined risk score 0-100

        Returns:
            Corresponding RiskLevel
        """
        if score <= 30:
            return RiskLevel.LOW
        if score <= 60:
            return RiskLevel.MEDIUM
        if score <= 80:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def get_response(self, level: RiskLevel) -> dict[str, Any]:
        """Get appropriate response for risk level.

        Implements AC17: Graduated response based on risk.

        Args:
            level: Risk level

        Returns:
            Response dict with action and rate_limit
        """
        return self.RESPONSES[level]


class AuditLoggerProtocol(Protocol):
    """Protocol for audit logger to avoid circular imports."""

    async def log_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Log an audit event."""
        ...


class AntiAbuseService:
    """Prevents abuse of free tier signups.

    Implements:
    - AC1: IP account limiting (max 3 accounts per IP)
    - AC6: IP-to-account mapping with 30-day TTL
    - AC2, AC7: Email domain validation with configurable blocklist
    - AC8: Audit logging for blocked signups
    """

    IP_ACCOUNT_LIMIT = 3
    IP_KEY_TTL = 30 * 24 * 60 * 60  # 30 days in seconds

    def __init__(
        self,
        redis: "Redis[str]",
        audit_logger: AuditLoggerProtocol,
    ) -> None:
        """Initialize anti-abuse service.

        Args:
            redis: Redis client for storing IP counters
            audit_logger: Audit logger for security events
        """
        self.redis = redis
        self.audit = audit_logger

    def _hash_ip(self, ip: str) -> str:
        """Hash IP address for privacy.

        Uses SHA256 truncated to 16 chars (64 bits) for:
        - GDPR compliance (no raw IPs stored)
        - Sufficient uniqueness for abuse tracking
        - Compact storage

        Args:
            ip: Raw IP address string

        Returns:
            16-character hex hash of the IP
        """
        return hashlib.sha256(ip.encode()).hexdigest()[:16]

    async def check_ip_account_limit(
        self, ip: str, is_datacenter: bool | None = None
    ) -> tuple[bool, str | None]:
        """Check if IP has exceeded account creation limit.

        Implements AC1: Block signup when IP has 3+ existing accounts.
        Implements AC13: Stricter limit (1) for datacenter/VPN IPs.

        Args:
            ip: Client IP address
            is_datacenter: Override datacenter detection (for testing)

        Returns:
            Tuple of (allowed: bool, error_message: str | None)
            - (True, None) if under limit, allowed to create account
            - (False, "Account limit reached") if at/over limit
        """
        ip_hash = self._hash_ip(ip)
        key = f"ip:accounts:{ip_hash}"

        count_str = await self.redis.get(key)
        current_count = int(count_str) if count_str else 0

        # AC13: Stricter limit for datacenter IPs
        if is_datacenter is None:
            is_datacenter = self.is_datacenter_ip(ip)

        effective_limit = 1 if is_datacenter else self.IP_ACCOUNT_LIMIT

        if current_count >= effective_limit:
            # Log blocked attempt (AC8)
            await self.audit.log_event(
                "signup_blocked_ip_limit",
                details={
                    "ip_hash": ip_hash,
                    "current_count": current_count,
                    "limit": effective_limit,
                    "is_datacenter": is_datacenter,
                },
            )
            return False, "Account limit reached"

        return True, None

    async def record_signup_ip(self, ip: str) -> None:
        """Record successful signup from IP.

        Implements AC6: Store IP-to-account mapping with 30-day TTL.

        Args:
            ip: Client IP address that successfully signed up
        """
        ip_hash = self._hash_ip(ip)
        key = f"ip:accounts:{ip_hash}"

        await self.redis.incr(key)
        await self.redis.expire(key, self.IP_KEY_TTL)

    def validate_business_email(
        self, email: str, _log_normalization: bool = True
    ) -> tuple[bool, str | None, str]:
        """Validate email is from business domain with normalization.

        Implements AC2: Block consumer email domains.
        Implements AC7: Use configurable blocklist from environment.
        Implements AC18: Email normalization before validation.
        Implements AC24: Root domain extraction for subdomain bypass prevention.

        Args:
            email: Email address to validate
            log_normalization: Whether to log if normalization was applied

        Returns:
            Tuple of (allowed: bool, error_message: str | None, normalized_email: str)
            - (True, None, normalized) if business email, allowed
            - (False, "Business email required", normalized) if consumer domain
        """
        # AC18: Normalize email first
        normalized = normalize_email(email)

        # AC24: Extract root domain to prevent subdomain bypass
        root_domain = extract_root_domain(normalized)

        # Check against blocklist using root domain
        if root_domain in settings.blocked_email_domains:
            return False, "Business email required", normalized

        # Also check the full domain (for subdomains of blocked domains)
        full_domain = normalized.split("@")[-1]
        if full_domain in settings.blocked_email_domains:
            return False, "Business email required", normalized

        return True, None, normalized

    def is_datacenter_ip(self, ip: str) -> bool:
        """Check if IP belongs to known datacenter ranges.

        Implements AC13: Detect datacenter/VPN IPs for stricter limits.

        Args:
            ip: IP address to check

        Returns:
            True if IP is in a known datacenter range
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            networks = _get_datacenter_networks()
            return any(ip_obj in network for network in networks)
        except ValueError:
            # Invalid IP address
            return False

    async def get_ip_context(self, ip: str) -> IPContext:
        """Get comprehensive IP context for risk scoring.

        Implements AC13: Enhanced IP intelligence.

        Args:
            ip: IP address to analyze

        Returns:
            IPContext with all IP-related signals
        """
        ip_hash = self._hash_ip(ip)
        key = f"ip:accounts:{ip_hash}"

        count_str = await self.redis.get(key)
        account_count = int(count_str) if count_str else 0

        return IPContext(
            ip_hash=ip_hash,
            account_count=account_count,
            is_datacenter=self.is_datacenter_ip(ip),
            is_vpn=False,  # Requires external service - placeholder
            is_tor=False,  # Could check known Tor exit nodes - placeholder
        )

    def analyze_email(self, email: str) -> EmailAnalysis:
        """Analyze email for risk scoring signals.

        Implements AC14: Domain-based risk signals.
        Implements AC18: Uses normalized email.
        Implements AC24: Uses root domain extraction.

        Args:
            email: Email address to analyze

        Returns:
            EmailAnalysis with all email-related signals
        """
        # AC18: Normalize email first
        normalized = normalize_email(email)
        domain = normalized.split("@")[-1]

        # AC24: Get root domain for accurate blocking
        root_domain = extract_root_domain(normalized)

        # Check if consumer domain (using root domain)
        is_consumer = root_domain in settings.blocked_email_domains

        # Check if disposable email domain
        is_disposable = (
            domain in DISPOSABLE_EMAIL_DOMAINS or root_domain in DISPOSABLE_EMAIL_DOMAINS
        )

        return EmailAnalysis(
            domain=domain,
            is_disposable=is_disposable,
            is_consumer=is_consumer,
            domain_age_days=None,  # Requires WHOIS lookup - placeholder
            has_mx_record=True,  # Requires DNS lookup - placeholder
            local_part_entropy=0.0,  # Could calculate Shannon entropy
        )

    async def calculate_signup_risk(
        self,
        ip: str,
        email: str,
        form_timing_seconds: float | None = None,
        device_fingerprint: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[int, RiskLevel, dict[str, Any]]:
        """Calculate comprehensive risk score for signup attempt.

        Implements AC12, AC16, AC17: Multi-signal abuse scoring.

        Args:
            ip: Client IP address
            email: User email address
            form_timing_seconds: Time to fill form (optional)
            device_fingerprint: Device fingerprint hash (optional)
            user_agent: User agent string (optional)

        Returns:
            Tuple of (score: int, level: RiskLevel, details: dict)
        """
        # Build context objects
        context = SignupContext(
            ip=ip,
            email=email,
            form_timing_seconds=form_timing_seconds,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
        )
        ip_ctx = await self.get_ip_context(ip)
        email_analysis = self.analyze_email(email)

        # Calculate risk score
        risk_scorer = AbuseRiskScore()
        score, level = risk_scorer.calculate(context, ip_ctx, email_analysis)

        # Log risk score calculation (AC22)
        details = {
            "ip_hash": ip_ctx.ip_hash,
            "email_domain": email_analysis.domain,
            "score": score,
            "level": level.value,
            "is_datacenter": ip_ctx.is_datacenter,
            "is_consumer_email": email_analysis.is_consumer,
            "account_count": ip_ctx.account_count,
            "form_timing": form_timing_seconds,
        }
        await self.audit.log_event("signup_risk_score_calculated", details=details)

        return score, level, details

    def get_graduated_response(self, level: RiskLevel) -> dict[str, Any]:
        """Get graduated response action for risk level.

        Implements AC17: Graduated response based on risk score.

        Args:
            level: Risk level from scoring

        Returns:
            Response dict with action and rate_limit
        """
        return AbuseRiskScore.RESPONSES[level]


# =============================================================================
# Email Normalization (AC18)
# =============================================================================


def normalize_email(email: str) -> str:
    """Normalize email to canonical form to prevent bypass attacks.

    Implements AC18: Email normalization before validation.

    Handles:
    - Plus aliases: user+tag@domain.com → user@domain.com
    - Gmail dot trick: john.doe@gmail.com → johndoe@gmail.com
    - googlemail.com alias: user@googlemail.com → user@gmail.com
    - Case normalization: User@Domain.COM → user@domain.com

    Args:
        email: Raw email address

    Returns:
        Normalized email address
    """
    if "@" not in email:
        return email.lower()

    local, domain = email.lower().split("@", 1)

    # Strip + aliases (works for most providers)
    if "+" in local:
        local = local.split("+")[0]

    # Gmail-specific normalizations
    if domain in ("gmail.com", "googlemail.com"):
        # Gmail ignores dots in local part
        local = local.replace(".", "")
        # Normalize googlemail.com to gmail.com
        domain = "gmail.com"

    return f"{local}@{domain}"


# =============================================================================
# Root Domain Extraction (AC24)
# =============================================================================


def extract_root_domain(email: str) -> str:
    """Extract root domain from email, ignoring subdomains.

    Implements AC24: Root domain extraction using Public Suffix List.

    Uses Mozilla's Public Suffix List for accurate extraction.

    Examples:
        user@sub.protonmail.com → protonmail.com
        user@mail.company.co.uk → company.co.uk
        user@deep.nested.sub.domain.com → domain.com

    Args:
        email: Email address

    Returns:
        Root domain (e.g., "protonmail.com")
    """
    domain = email.rsplit("@", maxsplit=1)[-1].lower()

    if HAS_TLDEXTRACT:
        extracted = tldextract.extract(domain)

        # Handle edge case: no registered domain
        if not extracted.domain:
            return domain

        # Combine domain + suffix (handles .co.uk, .com.au, etc.)
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return extracted.domain
    else:
        # Fallback: simple extraction (less accurate for .co.uk etc.)
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain


# =============================================================================
# Server-Side Form Timing (AC19)
# =============================================================================


class ServerSideTiming:
    """Track form timing server-side to prevent client-side spoofing.

    Implements AC19: Server-side timing measurement.

    Client-side X-Form-Timing header can be easily forged.
    Server-side timing cannot be spoofed.
    """

    SESSION_KEY_PREFIX = "session:timing:"
    SESSION_TTL = 3600  # 1 hour

    def __init__(self, redis: "Redis[str]") -> None:
        """Initialize timing service.

        Args:
            redis: Redis client
        """
        self.redis = redis

    async def start_session(self) -> str:
        """Start timing session and return secure session ID.

        Implements AC19: Server-side timing with secure session IDs.

        Returns:
            Secure session ID (43 chars, 256-bit entropy)
        """
        # Task 18: Use secrets.token_urlsafe for 256-bit entropy
        session_id = secrets.token_urlsafe(32)
        key = f"{self.SESSION_KEY_PREFIX}{session_id}"

        # Store with server nonce for additional security
        nonce = secrets.token_hex(16)
        value = f"{time.time()}:{nonce}"

        await self.redis.set(key, value, ex=self.SESSION_TTL)
        return session_id

    async def get_elapsed_time(self, session_id: str) -> float | None:
        """Get actual elapsed time since page load (unforgeable).

        Args:
            session_id: Session ID from start_session

        Returns:
            Elapsed time in seconds, or None if session not found
        """
        # Validate session ID format (prevent injection)
        if not session_id or len(session_id) != 43:  # base64 of 32 bytes
            return None

        key = f"{self.SESSION_KEY_PREFIX}{session_id}"
        value = await self.redis.get(key)

        if not value:
            return None

        # Handle both str and bytes from Redis
        if isinstance(value, bytes):
            value = value.decode()

        start_time = float(value.split(":")[0])
        elapsed = time.time() - start_time

        # Clean up after use (one-time use)
        await self.redis.delete(key)

        return elapsed

    async def cleanup_session(self, session_id: str) -> None:
        """Clean up timing session data.

        Args:
            session_id: Session ID to clean up
        """
        if session_id:
            key = f"{self.SESSION_KEY_PREFIX}{session_id}"
            await self.redis.delete(key)


# =============================================================================
# Webhook Idempotency (AC23)
# =============================================================================


class WebhookIdempotency:
    """Track processed webhook IDs to prevent replay attacks.

    Implements AC23: Webhook idempotency tracking.

    Even with valid signatures, attackers could replay webhooks
    if we don't track which ones we've already processed.
    """

    SEEN_KEY_PREFIX = "webhook:seen:"
    SEEN_TTL = 86400  # 24 hours

    def __init__(self, redis: "Redis[str]") -> None:
        """Initialize idempotency tracker.

        Args:
            redis: Redis client
        """
        self.redis = redis

    async def is_duplicate(self, svix_id: str | None) -> bool:
        """Check if webhook has already been processed.

        Uses SETNX for atomic check-and-set operation.

        Args:
            svix_id: Svix webhook ID from header

        Returns:
            True if this is a duplicate (already seen)
        """
        if not svix_id:
            return False  # Missing ID is handled by signature verification

        key = f"{self.SEEN_KEY_PREFIX}{svix_id}"
        # SETNX returns True if key was set (new), False if existed (duplicate)
        was_set = await self.redis.set(key, "1", nx=True, ex=self.SEEN_TTL)
        return not was_set  # Invert: not set = duplicate

    async def mark_processed(self, svix_id: str) -> None:
        """Explicitly mark webhook as processed.

        Args:
            svix_id: Svix webhook ID
        """
        if svix_id:
            key = f"{self.SEEN_KEY_PREFIX}{svix_id}"
            await self.redis.set(key, "1", ex=self.SEEN_TTL)


# =============================================================================
# Signup Velocity Monitoring (AC26)
# =============================================================================


class SignupVelocityMonitor:
    """Monitor global signup velocity to detect coordinated attacks.

    Implements AC26: Global signup velocity monitoring.

    Distributed Sybil attacks use many accounts, each under rate limits.
    Velocity monitoring detects unusual patterns across ALL signups.
    """

    VELOCITY_KEY_PREFIX = "signup:velocity:"
    THRESHOLD_PER_MINUTE = 10
    BUCKET_TTL = 120  # Keep 2 minutes of data

    def __init__(
        self,
        redis: "Redis[str]",
        audit_logger: "AuditLoggerProtocol | None" = None,
    ) -> None:
        """Initialize velocity monitor.

        Args:
            redis: Redis client
            audit_logger: Optional audit logger for events
        """
        self.redis = redis
        self.audit = audit_logger

    def _get_bucket_key(self) -> str:
        """Get current minute bucket key."""
        minute = int(time.time() // 60)
        return f"{self.VELOCITY_KEY_PREFIX}{minute}"

    async def record_signup(self) -> tuple[bool, int]:
        """Record signup and check if velocity threshold exceeded.

        Returns:
            Tuple of (under_threshold: bool, count: int)
            - (True, count) if under threshold (proceed normally)
            - (False, count) if over threshold (needs review)
        """
        key = self._get_bucket_key()

        # Atomic increment and get
        count = await self.redis.incr(key)
        await self.redis.expire(key, self.BUCKET_TTL)

        if count > self.THRESHOLD_PER_MINUTE:
            if self.audit:
                await self.audit.log_event(
                    "signup_velocity_exceeded",
                    details={
                        "count": count,
                        "threshold": self.THRESHOLD_PER_MINUTE,
                    },
                )
            return False, count

        return True, count

    async def get_current_velocity(self) -> int:
        """Get current signup count for monitoring.

        Returns:
            Current signup count in the current minute
        """
        key = self._get_bucket_key()
        count = await self.redis.get(key)
        return int(count) if count else 0


# =============================================================================
# GDPR Rate Limiter (AC25)
# =============================================================================


class GDPRRateLimiter:
    """Prevent abuse of GDPR deletion endpoint.

    Implements AC25: GDPR endpoint rate limiting.

    Attackers could use GDPR delete to reset their IP counters,
    then create new accounts in a loop.
    """

    COOLDOWN_DAYS = 30
    COOLDOWN_SECONDS = COOLDOWN_DAYS * 24 * 60 * 60
    KEY_PREFIX = "gdpr:delete:"

    def __init__(self, redis: "Redis[str]") -> None:
        """Initialize GDPR rate limiter.

        Args:
            redis: Redis client
        """
        self.redis = redis

    async def check_rate_limit(self, ip: str) -> tuple[bool, int | None]:
        """Check if GDPR deletion is rate limited for this IP.

        Args:
            ip: Client IP address

        Returns:
            Tuple of (allowed: bool, seconds_remaining: int | None)
            - (True, None) if allowed
            - (False, seconds_remaining) if rate limited
        """
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        key = f"{self.KEY_PREFIX}{ip_hash}"

        last_delete = await self.redis.get(key)
        if last_delete:
            # Handle both str and bytes from Redis
            if isinstance(last_delete, bytes):
                last_delete = last_delete.decode()
            elapsed = time.time() - float(last_delete)
            if elapsed < self.COOLDOWN_SECONDS:
                remaining = int(self.COOLDOWN_SECONDS - elapsed)
                return False, remaining

        return True, None

    async def record_deletion(self, ip: str) -> None:
        """Record GDPR deletion timestamp.

        Args:
            ip: Client IP address
        """
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        key = f"{self.KEY_PREFIX}{ip_hash}"
        await self.redis.set(key, str(time.time()), ex=self.COOLDOWN_SECONDS)


# =============================================================================
# Signup Review Queue (AC26)
# =============================================================================


@dataclass
class SignupReviewItem:
    """Item in the signup review queue."""

    clerk_id: str
    email: str
    ip_hash: str
    reason: str
    risk_score: int
    risk_level: str
    timestamp: float = field(default_factory=time.time)
    velocity_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "clerk_id": self.clerk_id,
            "email": self.email,
            "ip_hash": self.ip_hash,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
            "velocity_count": self.velocity_count,
        }


class SignupReviewQueue:
    """Queue for signups that require manual review.

    Implements AC26: Signup review queue for velocity-exceeded signups.

    When signup velocity exceeds threshold, signups are added to this queue
    for admin review instead of being blocked.
    """

    QUEUE_KEY = "signup:review_queue"
    QUEUE_TTL = 7 * 24 * 60 * 60  # Keep items for 7 days

    def __init__(
        self,
        redis: "Redis[str]",
        audit_logger: "AuditLoggerProtocol | None" = None,
    ) -> None:
        """Initialize review queue.

        Args:
            redis: Redis client
            audit_logger: Optional audit logger for events
        """
        self.redis = redis
        self.audit = audit_logger

    async def add_to_queue(self, item: SignupReviewItem) -> None:
        """Add a signup to the review queue.

        Args:
            item: SignupReviewItem to add
        """
        # Add to the list (LPUSH for newest first)
        await self.redis.lpush(self.QUEUE_KEY, json.dumps(item.to_dict()))

        # Trim to prevent unbounded growth (keep last 10000 items)
        await self.redis.ltrim(self.QUEUE_KEY, 0, 9999)

        if self.audit:
            await self.audit.log_event(
                "signup_added_to_review_queue",
                details={
                    "clerk_id": item.clerk_id,
                    "reason": item.reason,
                    "risk_score": item.risk_score,
                },
            )

    async def get_queue_length(self) -> int:
        """Get the number of items in the review queue.

        Returns:
            Number of pending reviews
        """
        return await self.redis.llen(self.QUEUE_KEY)
