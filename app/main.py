import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.classifier import InvalidIOC
from app.config import Settings, get_settings
from app.database import Database, InvestigationRepository
from app.schemas import AnalysisReport, AnalyzeRequest, InvestigationSummary, StatsResponse
from app.service import AnalysisService


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or get_settings()
    logging.basicConfig(level=config.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    database = Database(config)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.create()
        yield
        database.engine.dispose()

    app = FastAPI(title="Sentinel", version="1.0.0", description="Defensive threat-intelligence and IOC triage API", lifespan=lifespan)
    app.state.database = database; app.state.settings = config

    def db_session(): yield from database.session()

    @app.exception_handler(InvalidIOC)
    async def invalid_ioc_handler(_, exc: InvalidIOC):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=422, content={"detail":str(exc)})

    DatabaseSession = Annotated[Session, Depends(db_session)]

    @app.get("/health")
    def health(session: DatabaseSession):
        session.execute(text("SELECT 1"))
        return {"status":"ok","database":"ok"}

    @app.post("/api/analyze", response_model=AnalysisReport, status_code=201)
    async def analyze(request: AnalyzeRequest, session: DatabaseSession):
        return await AnalysisService(InvestigationRepository(session), config).analyze(request.ioc, request.force_refresh)

    @app.get("/api/investigations", response_model=list[InvestigationSummary])
    def investigations(session: DatabaseSession, limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0)):
        return InvestigationRepository(session).list(limit,offset)

    @app.get("/api/investigations/{investigation_id}", response_model=AnalysisReport)
    def investigation(investigation_id:int,session:DatabaseSession):
        report=InvestigationRepository(session).get(investigation_id)
        if not report: raise HTTPException(404,"Investigation not found")
        return report

    @app.get("/api/cve/{cve}", response_model=AnalysisReport)
    async def cve(cve:str,session:DatabaseSession,refresh:bool=False):
        return await AnalysisService(InvestigationRepository(session),config).analyze(cve,refresh)

    @app.get("/api/stats", response_model=StatsResponse)
    def stats(session:DatabaseSession): return InvestigationRepository(session).stats()
    return app


app = create_app()
