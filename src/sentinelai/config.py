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

    # LLM Reverse Proxy & Provider Configuration
    default_llm_provider: str = "ollama"
    llm_default_timeout_seconds: float = 60.0

    # Ollama Provider
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_timeout_seconds: float = 60.0

    # Gemini Provider (credentials loaded exclusively from environment)
    gemini_api_key: str | None = None
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_timeout_seconds: float = 60.0

    # Input Security Engine Configuration
    security_enabled: bool = True
    security_block_threshold: float = 0.60
    security_block_status_code: int = 403

    # Phase 4: Context, Data & Tool Security Configuration
    security_block_on_secrets: bool = True
    security_redact_pii: bool = False
    security_allowed_tools: list[str] = [
        "calculator",
        "search_docs",
        "get_weather",
        "read_metric",
        "query_database",
    ]
    security_blocked_tools: list[str] = [
        "execute_bash",
        "run_command",
        "shell_exec",
        "eval_code",
        "system_exec",
        "delete_database",
    ]

    # Phase 5: Output Protection Configuration
    output_protection_enabled: bool = True
    output_redact_pii: bool = True
    output_redact_secrets: bool = True
    output_block_critical_leaks: bool = True
    output_detect_prompt_leakage: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
