"""Application configuration for the RAT Detection Lab backend.

Defensive / simulation-only. Secrets are read from the environment (never
hardcoded, never committed). See ``.env.example`` for the full list.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="LAB_", extra="ignore"
    )

    # --- Environment / network posture -------------------------------------
    environment: str = Field(default="lab", description="Deployment label.")
    # Default exposure is localhost only. Do NOT bind to 0.0.0.0 in the lab.
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)

    # --- Payload security ---------------------------------------------------
    protocol_version: str = Field(default="1.0")
    # Per-device HMAC secrets are looked up from a registry; this is the
    # fallback lab secret used only for local development.
    hmac_secret: str = Field(
        default="dev-only-lab-secret-change-me",
        description="Fallback HMAC signing secret (dev only).",
    )
    # Payload freshness window, in seconds, for replay/expiration checks.
    payload_ttl_seconds: int = Field(default=30)
    # Maximum accepted payload size in bytes (RULE-008).
    max_payload_bytes: int = Field(default=8192)
    # How long a nonce is remembered for replay defense, in seconds.
    nonce_cache_ttl_seconds: int = Field(default=120)

    # --- Rate limiting ------------------------------------------------------
    rate_limit_per_minute: int = Field(default=60)

    # --- Database -----------------------------------------------------------
    # Synchronous SQLAlchemy URL. Defaults to a local SQLite file so the lab
    # runs without PostgreSQL; docker-compose points this at PostgreSQL.
    database_url: str = Field(default="sqlite:///./lab.db")

    # --- CORS ---------------------------------------------------------------
    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
