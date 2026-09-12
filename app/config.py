from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    database_url: str = "sqlite:///./sentinel.db"
    cache_ttl_seconds: int = Field(default=3600, ge=0)
    degraded_cache_ttl_seconds: int = Field(default=60, ge=0)
    provider_timeout_seconds: float = Field(default=10, gt=0, le=60)
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    urlhaus_base_url: str = "https://urlhaus-api.abuse.ch/v1"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
