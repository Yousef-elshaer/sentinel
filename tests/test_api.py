from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_health_and_validation(tmp_path):
    app=create_app(Settings(database_url=f"sqlite:///{tmp_path/'test.db'}",cache_ttl_seconds=0))
    with TestClient(app) as client:
        assert client.get("/health").json()=={"status":"ok","database":"ok"}
        response=client.post("/api/analyze",json={"ioc":"bad input"})
        assert response.status_code==422
        assert client.get("/api/investigations/999").status_code==404


def test_public_dashboard(tmp_path):
    app=create_app(Settings(database_url=f"sqlite:///{tmp_path/'test.db'}"))
    with TestClient(app) as client:
        response=client.get("/")
        assert response.status_code==200
        assert "Investigate indicators" in response.text
        assert 'aria-label="Indicator of compromise"' in response.text


def test_missing_keys_and_legacy_cache_are_unknown(tmp_path):
    from app.database import Investigation
    from app.schemas import ProviderResult, ProviderStatus

    app = create_app(Settings(database_url=f"sqlite:///{tmp_path/'test.db'}",
                              virustotal_api_key="", abuseipdb_api_key=""))
    with TestClient(app) as client:
        fresh = client.post("/api/analyze", json={"ioc": "8.8.8.8"}).json()
        assert fresh["risk_score"] is None and fresh["verdict"] == "UNKNOWN"
        assert not fresh["cached"]
        # Simulate an existing report written by the old scorer.
        with app.state.database.sessions() as session:
            row = Investigation(ioc="1.1.1.1", ioc_type="ipv4", risk_score=0, verdict="LOW",
                                provider_results=[ProviderResult(provider="x", status=ProviderStatus.SKIPPED).model_dump(mode="json")],
                                risk_explanations=["+0: No provider returned a positive malicious signal"])
            session.add(row)
            session.commit()
            legacy_id = row.id
        cached = client.post("/api/analyze", json={"ioc": "1.1.1.1"}).json()
        assert cached["cached"] and cached["risk_score"] is None and cached["verdict"] == "UNKNOWN"
        detail = client.get(f"/api/investigations/{legacy_id}").json()
        assert detail["risk_score"] is None and detail["verdict"] == "UNKNOWN"
        history = client.get("/api/investigations").json()
        assert all(r["risk_score"] is None and r["verdict"] == "UNKNOWN" for r in history)
        assert client.get("/api/stats").json()["verdict_counts"] == {"UNKNOWN": 2}
