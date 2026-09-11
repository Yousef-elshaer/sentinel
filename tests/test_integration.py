import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.config import Settings
from app.main import create_app


@respx.mock
def test_cve_analysis_cache_and_stats(tmp_path):
    url="https://example.test/kev.json"
    respx.get(url).mock(return_value=Response(200,json={"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache"}]}))
    settings=Settings(database_url=f"sqlite:///{tmp_path/'test.db'}",cisa_kev_url=url,cache_ttl_seconds=3600)
    with TestClient(create_app(settings)) as client:
        first=client.post("/api/analyze",json={"ioc":"cve-2021-44228"})
        assert first.status_code==201 and first.json()["risk_score"]==63
        second=client.post("/api/analyze",json={"ioc":"CVE-2021-44228"})
        assert second.json()["cached"] is True
        assert client.get(f"/api/investigations/{first.json()['id']}").status_code==200
        assert client.get("/api/stats").json()["total_investigations"]==1

@respx.mock
def test_provider_failure_does_not_break_analysis(tmp_path):
    url="https://example.test/kev.json"; respx.get(url).mock(return_value=Response(503))
    settings=Settings(database_url=f"sqlite:///{tmp_path/'test.db'}",cisa_kev_url=url,cache_ttl_seconds=0)
    with TestClient(create_app(settings)) as client:
        report=client.post("/api/analyze",json={"ioc":"CVE-2024-12345"})
        assert report.status_code==201 and report.json()["provider_results"][0]["status"]=="unavailable"
