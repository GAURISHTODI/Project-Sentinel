"""Runtime configuration, read from environment variables / .env (never hard-coded secrets)."""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    kafka_bootstrap: str = "127.0.0.1:29092"
    events_topic: str = "events.normalized"
    detections_topic: str = "detections"
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"))
    database_url: SecretStr = Field(
        default=SecretStr("postgresql://sentinel@localhost:5432/sentinel")
    )
    webhook_url: SecretStr = Field(default=SecretStr(""))  # Slack/Teams incoming webhook
    webhook_flavor: str = "slack"
    splunk_hec_url: str = "https://127.0.0.1:8088/services/collector/event"
    splunk_hec_token: SecretStr = Field(default=SecretStr(""))
    splunk_verify_tls: bool = False  # Splunk's dev container uses a self-signed certificate
    phishing_detector_enabled: bool = (
        False  # opt-in: the URL model fails on bare-domain-only training data
    )
    jwt_secret: SecretStr = Field(default=SecretStr(""))  # required to start the API (>= 32 chars)
    jwt_ttl_minutes: int = 30
    api_docs: bool = False  # expose /docs only in development
    llm_provider: str = "mock"
    llm_api_key: SecretStr = Field(default=SecretStr(""))


@lru_cache
def get_settings() -> Settings:
    return Settings()
