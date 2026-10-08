from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://user:password@localhost:5432/licensedb"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Security
    secret_key: str = "change-this-in-production"
    ed25519_private_key_path: str = "./keys/ed25519_private.pem"
    ed25519_public_key_path: str = "./keys/ed25519_public.pem"

    # Admin
    admin_email: str = "admin@yourdomain.com"
    admin_password: str = "change-this"

    # Session
    session_key_ttl_seconds: int = 300       # 5 minutes - client must refresh before this
    heartbeat_interval_seconds: int = 60      # client heartbeat every 60s
    grace_period_seconds: int = 180           # 3 min grace if server unreachable

    # Rate limiting
    rate_limit_activate: str = "5/minute"
    rate_limit_heartbeat: str = "30/minute"

    # App
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_debug: bool = False
    domain: str = "https://yourdomain.com"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
