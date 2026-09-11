import httpx

from app.classifier import classify_ioc
from app.config import Settings
from app.database import InvestigationRepository
from app.providers import query_providers
from app.schemas import AnalysisReport
from app.scoring import calculate_risk


class AnalysisService:
    def __init__(self, repository: InvestigationRepository, settings: Settings):
        self.repository, self.settings = repository, settings

    async def analyze(self, raw_ioc: str, force_refresh: bool = False) -> AnalysisReport:
        ioc = classify_ioc(raw_ioc)
        if not force_refresh:
            cached = self.repository.recent(ioc.value, self.settings.cache_ttl_seconds)
            if cached: return cached
        timeout = httpx.Timeout(self.settings.provider_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            results = await query_providers(ioc, client, self.settings)
        score, verdict, explanations = calculate_risk(results)
        return self.repository.save(ioc.value, ioc.type, score, verdict, results, explanations)

