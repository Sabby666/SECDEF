import os
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "SECDEF"
    APP_ENV: str = Field(default="development", description="development, staging, production")
    LOG_LEVEL: str = "INFO"
    
    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:////home/sabby/Projects/attack-surface-monitor/apps/control-plane/asm_dev.db",
        description="Async database connection string"
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string"
    )

    # Security & CORS
    SECRET_KEY: str = Field(
        default="DEV_ONLY_INSECURE_SECRET_KEY_CHANGE_IN_PRODUCTION_32BYTES",
        description="Master secret key for signing tokens"
    )
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    @property
    def is_development(self) -> bool:
        return self.APP_ENV.lower() == "development"


settings = Settings()
