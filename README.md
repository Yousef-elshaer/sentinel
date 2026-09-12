# Sentinel

**Defensive threat-intelligence and IOC triage in one explainable report.**

The deployed FastAPI service includes a responsive browser dashboard at `/` and interactive OpenAPI documentation at `/docs`.

Sentinel accepts an IP address, domain, URL, file hash, or CVE; identifies its type; queries relevant intelligence providers; normalizes their results; calculates a transparent 0–100 risk score; and stores the investigation. One unavailable provider never fails the complete analysis.

## Highlights

- Strict IPv4/IPv6, domain, URL, MD5, SHA-1, SHA-256, and CVE validation
- Async integrations for VirusTotal, AbuseIPDB, URLhaus, and CISA KEV
- Provider-specific timeout, authentication, rate-limit, outage, and response handling
- Explainable scoring with LOW, MEDIUM, HIGH, and CRITICAL verdicts
- Database-backed caching and investigation history
- FastAPI OpenAPI documentation and a separate Streamlit dashboard
- Mocked tests that do not use real API keys or quota
- Docker and PostgreSQL-ready SQLAlchemy design

> Sentinel's score is a project-specific triage methodology, not an industry-standard security score or a replacement for analyst judgment.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs`. In another terminal, run:

```bash
streamlit run dashboard/main.py
```

The dashboard opens at `http://localhost:8501`.

## API example

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"ioc":"CVE-2021-44228"}'
```

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/analyze` | Analyze or reuse a cached IOC report |
| GET | `/api/investigations` | Paginated investigation history |
| GET | `/api/investigations/{id}` | One stored report |
| GET | `/api/cve/{cve}` | CVE-specific convenience endpoint |
| GET | `/api/stats` | Verdict and IOC-type counts |
| GET | `/health` | API and database readiness |

## Configuration

Copy `.env.example` to `.env`. Add `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` for those providers. URLhaus and CISA KEV use public endpoints. Never commit `.env`.

## Architecture

The FastAPI route layer delegates to `AnalysisService`, which classifies and canonicalizes the IOC, checks the database cache, coordinates applicable provider adapters, applies the scoring engine, and persists the immutable report. Pydantic models isolate the rest of the application from provider-specific JSON. Streamlit is an API client and does not duplicate backend logic.

```text
Dashboard -> FastAPI -> Classifier -> Cache -> Provider coordinator
                                             -> Normalized results
                                             -> Scoring -> SQLite/PostgreSQL
```

## Tests

```bash
pytest --cov=app --cov-report=term-missing
ruff check .
```

The suite covers classification and edge cases, scoring boundaries, database caching, API validation, stored investigations, statistics, CISA normalization, and graceful provider outage handling.

## Docker

```bash
cp .env.example .env
docker compose up --build
```

API: `http://localhost:8000/docs` · Dashboard: `http://localhost:8501`

## Deploy to Render

The included `render.yaml` creates one free Python web service. Connect this repository as a Render Blueprint and deploy it; Render serves the browser dashboard and API from the same public URL. Add optional provider keys as secret environment variables in Render.

## Limitations

- Free provider tiers impose quotas and may return incomplete intelligence.
- Provider findings can contain false positives or stale data.
- Database caching is intentionally simple; a distributed deployment should use Redis or a shared cache.
- SQLite suits local development. Production concurrency should use PostgreSQL and migrations.
- This tool is defensive and does not download, execute, or interact with malware.

## Future work

- Alembic migrations and PostgreSQL deployment
- Authentication and per-user investigation collections
- Redis provider-response cache and background KEV refresh
- Exportable PDF/JSON reports and richer trend charts
- OpenTelemetry tracing and provider health metrics

## Screenshots

Add dashboard and OpenAPI screenshots here after running Sentinel locally with your configured provider accounts.
