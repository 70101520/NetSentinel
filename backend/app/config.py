from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str
    redis_url: str
    jwt_secret: str = Field(min_length=32)
    jwt_issuer: str = "netsentinel"
    access_token_minutes: int = Field(default=15, ge=5, le=60)
    agent_heartbeat_timeout_seconds: int = Field(default=180, ge=30)
    cors_origins: str = ""
    log_level: str = "INFO"
    @field_validator("jwt_secret")
    @classmethod
    def reject_placeholder(cls, value: str):
        if value.startswith("CHANGE_ME"): raise ValueError("JWT_SECRET must be replaced")
        return value
    @property
    def allowed_origins(self): return [v.strip() for v in self.cors_origins.split(",") if v.strip()]

@lru_cache
def get_settings(): return Settings()
settings = get_settings()
