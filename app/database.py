from collections.abc import Generator
from datetime import UTC, datetime, timedelta

from sqlalchemy import JSON, DateTime, Integer, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import Settings
from app.schemas import AnalysisReport, InvestigationSummary, IOCType, ProviderResult, StatsResponse


class Base(DeclarativeBase):
    pass


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc: Mapped[str] = mapped_column(String(2048), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    provider_results: Mapped[list[dict]] = mapped_column(JSON)
    risk_explanations: Mapped[list[str]] = mapped_column(JSON)


class Database:
    def __init__(self, settings: Settings):
        args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
        self.engine = create_engine(settings.database_url, connect_args=args)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create(self) -> None:
        Base.metadata.create_all(self.engine)

    def session(self) -> Generator[Session, None, None]:
        with self.sessions() as session:
            yield session


def to_report(row: Investigation, cached: bool = False) -> AnalysisReport:
    return AnalysisReport(
        id=row.id, ioc=row.ioc, ioc_type=IOCType(row.ioc_type), risk_score=row.risk_score,
        verdict=row.verdict, created_at=row.created_at,
        provider_results=[ProviderResult.model_validate(item) for item in row.provider_results],
        risk_explanations=row.risk_explanations, cached=cached,
    )


class InvestigationRepository:
    def __init__(self, session: Session): self.session = session

    def save(self, ioc: str, ioc_type: IOCType, score: int, verdict: str,
             results: list[ProviderResult], explanations: list[str]) -> AnalysisReport:
        row = Investigation(ioc=ioc, ioc_type=ioc_type.value, risk_score=score, verdict=verdict,
                            provider_results=[r.model_dump(mode="json") for r in results],
                            risk_explanations=explanations)
        self.session.add(row); self.session.commit(); self.session.refresh(row)
        return to_report(row)

    def get(self, investigation_id: int) -> AnalysisReport | None:
        row = self.session.get(Investigation, investigation_id)
        return to_report(row) if row else None

    def recent(self, ioc: str, ttl_seconds: int) -> AnalysisReport | None:
        cutoff = datetime.now(UTC) - timedelta(seconds=ttl_seconds)
        row = self.session.scalar(select(Investigation).where(
            Investigation.ioc == ioc, Investigation.created_at >= cutoff
        ).order_by(Investigation.created_at.desc()).limit(1))
        return to_report(row, cached=True) if row else None

    def list(self, limit: int, offset: int) -> list[InvestigationSummary]:
        rows = self.session.scalars(select(Investigation).order_by(
            Investigation.created_at.desc()).limit(limit).offset(offset)).all()
        return [InvestigationSummary.model_validate(row) for row in rows]

    def stats(self) -> StatsResponse:
        total = self.session.scalar(select(func.count()).select_from(Investigation)) or 0
        verdicts = dict(self.session.execute(select(Investigation.verdict, func.count()).group_by(Investigation.verdict)).all())
        types = dict(self.session.execute(select(Investigation.ioc_type, func.count()).group_by(Investigation.ioc_type)).all())
        return StatsResponse(total_investigations=total, verdict_counts=verdicts, type_counts=types)
