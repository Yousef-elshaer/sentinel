import httpx
import pytest

from app.classifier import classify_ioc
from app.config import Settings
from app.providers import CISAKEV, AbuseIPDB, URLhaus, VirusTotal
from app.schemas import ProviderStatus


def client_for(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_virustotal_maps_detection_statistics():
    def handler(request):
        assert request.headers["x-apikey"] == "test-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 4, "harmless": 66},
                        "categories": {"vendor": "phishing"},
                        "reputation": -12,
                    }
                }
            },
        )

    async with client_for(handler) as client:
        result = await VirusTotal(
            client, Settings(virustotal_api_key="test-key")
        ).safe_lookup(classify_ioc("example.com"))

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is True
    assert result.malicious_detections == 4
    assert result.total_detections == 70
    assert result.categories == ["phishing"]


@pytest.mark.asyncio
async def test_abuseipdb_maps_confidence_and_reports():
    def handler(request):
        assert request.url.params["ipAddress"] == "8.8.8.8"
        return httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 75,
                    "totalReports": 8,
                    "countryCode": "US",
                    "usageType": "Data Center",
                }
            },
        )

    async with client_for(handler) as client:
        result = await AbuseIPDB(
            client, Settings(abuseipdb_api_key="test-key")
        ).safe_lookup(classify_ioc("8.8.8.8"))

    assert result.malicious is True
    assert result.confidence == 75
    assert result.malicious_detections == 8


@pytest.mark.asyncio
async def test_urlhaus_reports_no_match_as_clean():
    async with client_for(
        lambda _: httpx.Response(200, json={"query_status": "no_results"})
    ) as client:
        result = await URLhaus(client, Settings()).safe_lookup(
            classify_ioc("https://example.com/path")
        )

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is False
    assert result.confidence == 0


@pytest.mark.asyncio
async def test_cisa_kev_handles_timeout():
    def handler(request):
        raise httpx.ReadTimeout("slow provider", request=request)

    async with client_for(handler) as client:
        result = await CISAKEV(client, Settings()).safe_lookup(
            classify_ioc("CVE-2024-12345")
        )

    assert result.status == ProviderStatus.TIMEOUT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(401, ProviderStatus.AUTH_ERROR), (403, ProviderStatus.AUTH_ERROR),
     (429, ProviderStatus.RATE_LIMITED), (503, ProviderStatus.UNAVAILABLE)],
)
async def test_provider_http_failures_are_normalized(status_code, expected):
    async with client_for(lambda _: httpx.Response(status_code)) as client:
        result = await CISAKEV(client, Settings()).safe_lookup(
            classify_ioc("CVE-2024-12345")
        )

    assert result.status == expected
    assert str(status_code) in result.error


@pytest.mark.asyncio
async def test_missing_api_key_skips_paid_provider():
    async with client_for(lambda _: pytest.fail("No request should be sent")) as client:
        result = await VirusTotal(client, Settings()).safe_lookup(
            classify_ioc("example.com")
        )

    assert result.status == ProviderStatus.SKIPPED
