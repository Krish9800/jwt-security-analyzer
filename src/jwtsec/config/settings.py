"""Runtime configuration settings for jwtsec."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable override support."""

    app_name: str = "JWT Security Analyzer"
    version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False

    # Token Scanning & Cracking Settings
    max_token_length: int = 16384
    allow_none_algorithm: bool = False
    enable_bruteforce: bool = True
    max_crack_words: int = 10000
    clock_skew_leeway_seconds: int = 60

    # Lab Server Config
    lab_host: str = "127.0.0.1"
    lab_port: int = 8082

    model_config = SettingsConfigDict(
        env_prefix="JWTSEC_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return singleton configuration settings."""
    return Settings()
