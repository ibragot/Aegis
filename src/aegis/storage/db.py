"""Relational storage for events, alerts, incidents, reports - and the entity graph.

Why PostgreSQL for a graph? The project brief suggests "build the relationships
yourself in PostgreSQL first": an `entities` table (nodes) and a
`relationships` table (edges, primary key = (src, dst, type)) is all a property
graph needs. Neighbourhood queries are simple indexed lookups, and the
analysis itself (paths, centrality) happens in NetworkX - see aegis/graph.
`aegis graph export-cypher` produces a Neo4j import if you want to explore the
same graph with Cypher.

All writes are *upserts* keyed on deterministic ids, so replaying the same Kafka
messages twice (at-least-once delivery) cannot create duplicates.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    String,
    create_engine,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from aegis.schema import Alert, Event, Incident, InvestigationReport


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(120))
    outcome: Mapped[str] = mapped_column(String(10))
    principal: Mapped[str | None] = mapped_column(String(200), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class AlertRow(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    detector: Mapped[str] = mapped_column(String(10))
    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(10))
    incident_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    data: Mapped[dict] = mapped_column(JSON)


class IncidentRow(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(10), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict] = mapped_column(JSON)


class EntityRow(Base):
    __tablename__ = "entities"
    id: Mapped[str] = mapped_column(String(300), primary_key=True)  # "type:value"
    type: Mapped[str] = mapped_column(String(30), index=True)
    value: Mapped[str] = mapped_column(String(260))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)


class RelationshipRow(Base):
    __tablename__ = "relationships"
    src: Mapped[str] = mapped_column(String(300), primary_key=True)
    dst: Mapped[str] = mapped_column(String(300), primary_key=True, index=True)
    type: Mapped[str] = mapped_column(String(40), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    count: Mapped[int] = mapped_column(Integer, default=1)
    last_event_id: Mapped[str | None] = mapped_column(String(40))


class ReportRow(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    generated_by: Mapped[str] = mapped_column(String(60))
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict] = mapped_column(JSON)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _dump(model) -> dict:
    return model.model_dump(mode="json")


class Repository:
    def __init__(self, url: str):
        kwargs: dict[str, Any] = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if url in ("sqlite://", "sqlite:///:memory:"):
                kwargs["poolclass"] = StaticPool  # one shared in-memory DB across threads
            else:
                Path(url.replace("sqlite:///", "")).parent.mkdir(parents=True, exist_ok=True)
        else:
            kwargs["pool_pre_ping"] = True
            kwargs["pool_size"] = 5
        self.engine = create_engine(url, **kwargs)
        self.dialect = self.engine.dialect.name
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    # ------------------------------------------------------------- upsert helper
    def _insert(self, table):
        if self.dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        return insert(table)

    # ------------------------------------------------------------- events
    def save_events(self, events: Iterable[Event]) -> int:
        rows = [
            {"event_id": e.event_id, "ts": e.timestamp, "source": e.source, "category": e.category,
             "action": e.action[:120], "outcome": e.outcome, "principal": e.principal, "src_ip": e.src_ip,
             "data": _dump(e)}
            for e in events
        ]
        if not rows:
            return 0
        with self.Session.begin() as s:
            s.execute(self._insert(EventRow).values(rows).on_conflict_do_nothing(index_elements=["event_id"]))
        return len(rows)

    def get_events(self, ids: list[str]) -> list[Event]:
        if not ids:
            return []
        with self.Session() as s:
            rows = s.scalars(select(EventRow).where(EventRow.event_id.in_(ids)).order_by(EventRow.ts)).all()
            return [Event(**r.data) for r in rows]

    def recent_events(self, limit: int = 100) -> list[Event]:
        with self.Session() as s:
            rows = s.scalars(select(EventRow).order_by(EventRow.ts.desc()).limit(limit)).all()
            return [Event(**r.data) for r in rows]

    # ------------------------------------------------------------- alerts
    def save_alert(self, alert: Alert, incident_id: int | None = None) -> None:
        row = {"alert_id": alert.alert_id, "created_at": alert.created_at, "event_time": alert.event_time,
               "detector": alert.detector, "rule_id": alert.rule_id, "severity": alert.severity.value,
               "incident_id": incident_id, "data": _dump(alert)}
        with self.Session.begin() as s:
            stmt = self._insert(AlertRow).values(row)
            s.execute(stmt.on_conflict_do_update(index_elements=["alert_id"],
                                                 set_={"incident_id": stmt.excluded.incident_id}))

    def get_alerts(self, ids: list[str]) -> list[Alert]:
        if not ids:
            return []
        with self.Session() as s:
            rows = s.scalars(select(AlertRow).where(AlertRow.alert_id.in_(ids)).order_by(AlertRow.event_time)).all()
            return [Alert(**r.data) for r in rows]

    def list_alerts(self, limit: int = 200, incident_id: int | None = None) -> list[tuple[Alert, int | None]]:
        with self.Session() as s:
            q = select(AlertRow).order_by(AlertRow.event_time.desc()).limit(limit)
            if incident_id is not None:
                q = q.where(AlertRow.incident_id == incident_id)
            return [(Alert(**r.data), r.incident_id) for r in s.scalars(q).all()]

    def reassign_alerts(self, from_ids: list[int], to_id: int) -> None:
        with self.Session.begin() as s:
            s.execute(update(AlertRow).where(AlertRow.incident_id.in_(from_ids)).values(incident_id=to_id))

    # ------------------------------------------------------------- incidents
    def next_incident_id(self) -> int:
        with self.Session() as s:
            return int(s.scalar(select(func.coalesce(func.max(IncidentRow.incident_id), 481))) or 481) + 1

    def save_incident(self, inc: Incident) -> None:
        row = {"incident_id": inc.incident_id, "title": inc.title[:300], "status": inc.status,
               "risk_score": inc.risk_score, "risk_level": inc.risk_level, "first_seen": inc.first_seen,
               "last_seen": inc.last_seen, "updated_at": inc.updated_at, "data": _dump(inc)}
        with self.Session.begin() as s:
            stmt = self._insert(IncidentRow).values(row)
            s.execute(stmt.on_conflict_do_update(index_elements=["incident_id"],
                                                 set_={k: stmt.excluded[k] for k in row if k != "incident_id"}))

    def delete_incidents(self, ids: list[int]) -> None:
        with self.Session.begin() as s:
            for row in s.scalars(select(IncidentRow).where(IncidentRow.incident_id.in_(ids))).all():
                s.delete(row)

    def get_incident(self, incident_id: int) -> Incident | None:
        with self.Session() as s:
            row = s.get(IncidentRow, incident_id)
            return Incident(**row.data) if row else None

    def list_incidents(self, limit: int = 100, status: str | None = None) -> list[Incident]:
        with self.Session() as s:
            q = select(IncidentRow).order_by(IncidentRow.risk_score.desc(), IncidentRow.last_seen.desc()).limit(limit)
            if status:
                q = q.where(IncidentRow.status == status)
            return [Incident(**r.data) for r in s.scalars(q).all()]

    def open_incidents_since(self, since: datetime) -> list[Incident]:
        with self.Session() as s:
            q = select(IncidentRow).where(IncidentRow.status != "closed", IncidentRow.last_seen >= since)
            return [Incident(**r.data) for r in s.scalars(q).all()]

    # ------------------------------------------------------------- graph
    def upsert_graph(self, nodes: list[dict], edges: list[dict]) -> None:
        if not nodes and not edges:
            return
        with self.Session.begin() as s:
            if nodes:
                merged: dict[str, dict] = {}
                for n in nodes:  # collapse duplicates inside one batch
                    m = merged.setdefault(n["id"], {**n, "event_count": 0})
                    m["event_count"] += 1
                    m["first_seen"] = min(m["first_seen"], n["first_seen"])
                    m["last_seen"] = max(m["last_seen"], n["last_seen"])
                    m["attributes"] = {**m.get("attributes", {}), **n.get("attributes", {})}
                stmt = self._insert(EntityRow).values(list(merged.values()))
                s.execute(stmt.on_conflict_do_update(index_elements=["id"], set_={
                    "last_seen": func.max(EntityRow.last_seen, stmt.excluded.last_seen) if self.dialect == "sqlite"
                    else func.greatest(EntityRow.last_seen, stmt.excluded.last_seen),
                    "event_count": EntityRow.event_count + stmt.excluded.event_count,
                    "attributes": stmt.excluded.attributes,
                }))
            if edges:
                merged_e: dict[tuple, dict] = {}
                for e in edges:
                    k = (e["src"], e["dst"], e["type"])
                    m = merged_e.setdefault(k, {**e, "count": 0})
                    m["count"] += 1
                    m["last_seen"] = max(m["last_seen"], e["last_seen"])
                    m["last_event_id"] = e["last_event_id"]
                stmt = self._insert(RelationshipRow).values(list(merged_e.values()))
                s.execute(stmt.on_conflict_do_update(index_elements=["src", "dst", "type"], set_={
                    "last_seen": stmt.excluded.last_seen,
                    "count": RelationshipRow.count + stmt.excluded.count,
                    "last_event_id": stmt.excluded.last_event_id,
                }))

    def edges_touching(self, entity_ids: list[str], types: list[str] | None = None, limit: int = 2000) -> list[dict]:
        if not entity_ids:
            return []
        with self.Session() as s:
            q = select(RelationshipRow).where(or_(RelationshipRow.src.in_(entity_ids),
                                                  RelationshipRow.dst.in_(entity_ids)))
            if types:
                q = q.where(RelationshipRow.type.in_(types))
            rows = s.scalars(q.order_by(RelationshipRow.last_seen.desc()).limit(limit)).all()
            return [{"src": r.src, "dst": r.dst, "type": r.type, "count": r.count,
                     "first_seen": _aware(r.first_seen), "last_seen": _aware(r.last_seen)} for r in rows]

    def get_entities(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        with self.Session() as s:
            rows = s.scalars(select(EntityRow).where(EntityRow.id.in_(ids))).all()
            return [{"id": r.id, "type": r.type, "value": r.value, "first_seen": _aware(r.first_seen),
                     "last_seen": _aware(r.last_seen), "event_count": r.event_count,
                     "attributes": r.attributes or {}} for r in rows]

    def all_edges(self, limit: int = 50000) -> list[dict]:
        with self.Session() as s:
            rows = s.scalars(select(RelationshipRow).limit(limit)).all()
            return [{"src": r.src, "dst": r.dst, "type": r.type, "count": r.count} for r in rows]

    def all_entities(self, limit: int = 50000) -> list[dict]:
        with self.Session() as s:
            rows = s.scalars(select(EntityRow).limit(limit)).all()
            return [{"id": r.id, "type": r.type, "value": r.value, "attributes": r.attributes or {}} for r in rows]

    # ------------------------------------------------------------- reports
    def save_report(self, report: InvestigationReport, alert_count: int) -> None:
        with self.Session.begin() as s:
            s.add(ReportRow(incident_id=report.incident_id, created_at=report.generated_at,
                            generated_by=report.generated_by, alert_count=alert_count, data=_dump(report)))

    def latest_report(self, incident_id: int) -> tuple[InvestigationReport, int] | None:
        with self.Session() as s:
            row = s.scalars(select(ReportRow).where(ReportRow.incident_id == incident_id)
                            .order_by(ReportRow.id.desc()).limit(1)).first()
            return (InvestigationReport(**row.data), row.alert_count) if row else None

    # ------------------------------------------------------------- stats
    def stats(self) -> dict:
        with self.Session() as s:
            events = s.scalar(select(func.count()).select_from(EventRow)) or 0
            alerts = s.scalar(select(func.count()).select_from(AlertRow)) or 0
            by_level = dict(s.execute(select(IncidentRow.risk_level, func.count())
                                      .where(IncidentRow.status != "closed").group_by(IncidentRow.risk_level)).all())
            by_source = dict(s.execute(select(EventRow.source, func.count()).group_by(EventRow.source)).all())
            by_rule = s.execute(select(AlertRow.rule_id, func.count()).group_by(AlertRow.rule_id)
                                .order_by(func.count().desc()).limit(10)).all()
            by_detector = dict(s.execute(select(AlertRow.detector, func.count()).group_by(AlertRow.detector)).all())
            entities = s.scalar(select(func.count()).select_from(EntityRow)) or 0
            edges = s.scalar(select(func.count()).select_from(RelationshipRow)) or 0
            last_event = s.scalar(select(func.max(EventRow.ts)))
        return {
            "events": events, "alerts": alerts, "open_incidents_by_level": by_level, "events_by_source": by_source,
            "top_rules": [{"rule_id": r, "count": c} for r, c in by_rule], "alerts_by_detector": by_detector,
            "graph": {"entities": entities, "relationships": edges},
            "last_event_at": _aware(last_event).isoformat() if last_event else None,
        }


def create_repository(url: str | None = None) -> Repository:
    from aegis.config import get_settings

    return Repository(url or get_settings().database_url)
