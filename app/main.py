import logging
from collections.abc import Generator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.classifier import InvalidIOC
from app.config import Settings, get_settings
from app.database import Database, InvestigationRepository
from app.schemas import AnalysisReport, AnalyzeRequest, InvestigationSummary, StatsResponse
from app.service import AnalysisService
from app.web import dashboard

APP_VERSION = "1.0.0"
logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or get_settings()
    logging.basicConfig(level=config.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    database = Database(config)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.create()
        logger.info("Sentinel database initialized")
        yield
        database.engine.dispose()
        logger.info("Sentinel database connection disposed")

    app = FastAPI(
        title="Sentinel",
        version=APP_VERSION,
        description="Defensive threat-intelligence and IOC triage API",
        lifespan=lifespan,
        openapi_tags=[
            {"name": "analysis", "description": "Analyze indicators and retrieve reports."},
            {"name": "operations", "description": "Service readiness and aggregate statistics."},
        ],
    )
    app.state.database = database
    app.state.settings = config

    def db_session() -> Generator[Session, None, None]:
        yield from database.session()

    @app.exception_handler(InvalidIOC)
    async def invalid_ioc_handler(_: Request, exc: InvalidIOC):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=422, content={"detail": str(exc)})

    DatabaseSession = Annotated[Session, Depends(db_session)]

    @app.get("/", include_in_schema=False)
    def web_dashboard():
        return dashboard()

    @app.get("/health", tags=["operations"], summary="Check service readiness")
    def health(session: DatabaseSession, response: Response):
        session.execute(text("SELECT 1"))
        response.headers["Cache-Control"] = "no-store"
        return {"status": "ok", "database": "ok"}

    @app.post("/api/analyze", response_model=AnalysisReport, status_code=201, tags=["analysis"])
    async def analyze(request: AnalyzeRequest, session: DatabaseSession):
        return await AnalysisService(InvestigationRepository(session), config).analyze(request.ioc, request.force_refresh)

    @app.get("/api/investigations", response_model=list[InvestigationSummary], tags=["analysis"])
    def investigations(
        session: DatabaseSession,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ):
        return InvestigationRepository(session).list(limit, offset)

    @app.get("/api/investigations/{investigation_id}", response_model=AnalysisReport, tags=["analysis"])
    def investigation(investigation_id: int, session: DatabaseSession):
        report = InvestigationRepository(session).get(investigation_id)
        if not report:
            raise HTTPException(404, "Investigation not found")
        return report

    @app.get("/api/cve/{cve}", response_model=AnalysisReport, tags=["analysis"])
    async def cve(cve: str, session: DatabaseSession, refresh: bool = False):
        return await AnalysisService(InvestigationRepository(session), config).analyze(cve, refresh)

    @app.get("/api/stats", response_model=StatsResponse, tags=["operations"])
    def stats(session: DatabaseSession):
        return InvestigationRepository(session).stats()

    return app


app = create_app()
