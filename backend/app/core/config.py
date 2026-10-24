"""Application settings, loaded from environment variables (see .env.example)."""

from __future__ import annotations

import functools
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PKO_", env_file=".env", extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    api_title: str = "F5 PacketOps API"

    # MongoDB
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "packetops"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_eager: bool = False  # Run analysis inline (tests and single-process dev only).

    # Object storage
    storage_backend: Literal["local", "s3"] = "local"
    storage_local_root: str = "./var/storage"
    s3_endpoint_url: str | None = None
    s3_bucket: str = "packetops-evidence"
    s3_region: str = "us-east-1"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_server_side_encryption: str | None = "AES256"

    # Worker scratch space and derived-data cache
    work_dir: str = "./var/work"
    cache_dir: str = "./var/cache"

    # Authentication
    auth_mode: Literal["dev", "oidc"] = "dev"
    dev_jwt_secret: str = Field(default="change-me-dev-only-secret-at-least-32-bytes", min_length=32)
    jwt_ttl_minutes: int = 480
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_client_id: str | None = None  # public SPA client id (authorization code + PKCE)
    oidc_jwks_url: str | None = None
    oidc_tenant_claim: str = "tenant"
    oidc_roles_claim: str = "roles"
    oidc_email_claim: str = "email"

    # Limits
    max_upload_bytes: int = 2 * 1024 * 1024 * 1024
    tenant_storage_quota_bytes: int = 50 * 1024 * 1024 * 1024
    max_packets_per_capture: int = 20_000_000
    max_concurrent_analyses_per_tenant: int = 3
    analysis_timeout_s: int = 3600
    tshark_path: str | None = None
    tshark_memory_limit_bytes: int = 6 * 1024 * 1024 * 1024
    max_flows_tracked: int = 500_000
    evidence_refs_per_kind: int = 50

    # Data protection
    redact_query_strings: bool = True
    retention_days_default: int = 90

    # AI provider
    llm_provider: Literal["none", "openai_compatible", "anthropic"] = "none"
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_timeout_s: int = 60
    llm_redact_addresses: bool = True

    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split(cls, v):
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    if s.is_production:
        if s.auth_mode == "dev":
            raise RuntimeError("PKO_AUTH_MODE=dev is not allowed in production")
        if s.celery_eager:
            raise RuntimeError("PKO_CELERY_EAGER is not allowed in production")
    return s
