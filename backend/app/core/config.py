"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Annotated

from pydantic import BeforeValidator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _parse_comma_separated_set(v: str | set[str]) -> set[str]:
    """Parse comma-separated string into a set."""
    if isinstance(v, set):
        return v
    if isinstance(v, str):
        return {d.strip().lower() for d in v.split(",") if d.strip()}
    return set()


CommaSeparatedSet = Annotated[set[str], BeforeValidator(_parse_comma_separated_set)]


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_env: str = "development"
    debug: bool = True
    secret_key: str = "your-secret-key-here-change-in-production"

    # API
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/osint"
    database_url_sync: str = "postgresql://postgres:postgres@localhost:5432/osint"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    # Clerk Auth
    clerk_secret_key: str = ""
    clerk_publishable_key: str = ""
    clerk_webhook_secret: str = ""
    clerk_issuer: str = ""  # e.g., "https://your-app.clerk.accounts.dev"

    # LLM
    openai_api_key: str = ""
    litellm_model: str = "gpt-4-turbo"

    # Rate Limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_day: int = 1000

    # Feature Flags
    enable_quick_check: bool = True
    enable_graph_visualization: bool = True
    enable_ai_hypothesis: bool = True

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Audit
    audit_hmac_secret: str = "change-this-secret-in-production"

    # Anti-abuse settings (AC2, AC7)
    blocked_email_domains: CommaSeparatedSet = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "protonmail.com",
        "icloud.com",
        "mail.com",
        "aol.com",
        "yandex.com",
        "qq.com",
        "163.com",
        "live.com",
    }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
