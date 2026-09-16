from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_health_and_validation(tmp_path):
    app=create_app(Settings(database_url=f"sqlite:///{tmp_path/'test.db'}",cache_ttl_seconds=0))
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.json() == {"status": "ok", "database": "ok"}
        assert health.headers["cache-control"] == "no-store"
        response=client.post("/api/analyze",json={"ioc":"bad input"})
        assert response.status_code==422
        assert client.get("/api/investigations/999").status_code==404


def test_openapi_groups_analysis_and_operations(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path/'test.db'}"))
    with TestClient(app) as client:
        schema = client.get("/openapi.json").json()
        assert schema["paths"]["/api/analyze"]["post"]["tags"] == ["analysis"]
        assert schema["paths"]["/health"]["get"]["tags"] == ["operations"]


def test_public_dashboard(tmp_path):
    app=create_app(Settings(database_url=f"sqlite:///{tmp_path/'test.db'}"))
    with TestClient(app) as client:
        response=client.get("/")
        assert response.status_code==200
        assert "Investigate indicators" in response.text
        assert 'aria-label="Indicator of compromise"' in response.text
