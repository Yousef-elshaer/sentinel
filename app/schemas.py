from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class ProviderStatus(StrEnum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    AUTH_ERROR = "auth_error"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    INVALID_RESPONSE = "invalid_response"


class ProviderResult(BaseModel):
    provider: str
    status: ProviderStatus
    malicious: bool | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    malicious_detections: int | None = Field(default=None, ge=0)
    total_detections: int | None = Field(default=None, ge=0)
    categories: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime | None = None
    error: str | None = None


class AnalyzeRequest(BaseModel):
    ioc: str = Field(min_length=1, max_length=2048)
    force_refresh: bool = False


class AnalysisReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ioc: str
    ioc_type: IOCType
    risk_score: int | None
    verdict: str
    created_at: datetime
    provider_results: list[ProviderResult]
    risk_explanations: list[str]
    cached: bool = False


class InvestigationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ioc: str
    ioc_type: IOCType
    risk_score: int | None
    verdict: str
    created_at: datetime


class StatsResponse(BaseModel):
    total_investigations: int
    verdict_counts: dict[str, int]
    type_counts: dict[str, int]

