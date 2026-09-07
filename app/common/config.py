"""Configuration settings loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # SpiceDB configuration
    spicedb_endpoint: str = "localhost:50051"
    spicedb_preshared_key: str = "secret-preshared-key"
    spicedb_insecure: bool = True

    # Redis configuration
    redis_url: str = "redis://localhost:6379/0"

    # Service ports
    gateway_port: int = 8000
    gateway_host: str = "0.0.0.0"
    trust_engine_port: int = 8001
    trust_engine_host: str = "0.0.0.0"


settings = Settings()
