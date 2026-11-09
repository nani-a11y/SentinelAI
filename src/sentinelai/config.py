from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables or .env."""

    app_name: str = "SentinelAI"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    # PostgreSQL configuration (lightweight asyncpg connector)
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/sentinelai"
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_timeout_seconds: float = 3.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
