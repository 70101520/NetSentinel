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
    db_pool_size: int = Field(default=10, ge=2, le=100)
    db_max_overflow: int = Field(default=20, ge=0, le=200)
    max_page_size: int = Field(default=100, ge=20, le=500)
    service_token_pepper: str = Field(min_length=32)
    telemetry_stream: str = "netsentinel:telemetry"
    telemetry_group: str = "telemetry-workers"
    telemetry_dlq_stream: str = "netsentinel:telemetry:dlq"
    telemetry_max_batch_size: int = Field(default=500, ge=1, le=1000)
    telemetry_max_body_bytes: int = Field(default=2_097_152, ge=65_536, le=10_485_760)
    telemetry_rate_limit_events: int = Field(default=5000, ge=1)
    telemetry_rate_window_seconds: int = Field(default=60, ge=1)
    telemetry_queue_warning: int = Field(default=50_000, ge=100)
    telemetry_queue_critical: int = Field(default=100_000, ge=1000)
    telemetry_worker_batch_size: int = Field(default=500, ge=1, le=1000)
    telemetry_block_ms: int = Field(default=2000, ge=100, le=30000)
    telemetry_reclaim_idle_ms: int = Field(default=30000, ge=1000)
    telemetry_max_attempts: int = Field(default=5, ge=1, le=100)
    telemetry_db_retry_base_seconds: float = Field(default=1, ge=.1, le=60)
    @field_validator("jwt_secret")
    @classmethod
    def reject_placeholder(cls, value: str):
        if value.startswith("CHANGE_ME"): raise ValueError("JWT_SECRET must be replaced")
        return value
    @field_validator("service_token_pepper")
    @classmethod
    def reject_token_placeholder(cls, value: str):
        if value.startswith("CHANGE_ME"): raise ValueError("SERVICE_TOKEN_PEPPER must be replaced")
        return value
    @property
    def allowed_origins(self): return [v.strip() for v in self.cors_origins.split(",") if v.strip()]

@lru_cache
def get_settings(): return Settings()
settings = get_settings()
