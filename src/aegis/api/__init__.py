"""REST API (FastAPI) + the security dashboard (static single-page app).

Two modes:
* **local**  - the API owns an in-process `LocalPipeline` (no infrastructure); `aegis demo --serve`.
* **remote** - the API is just another microservice: it reads PostgreSQL and publishes
  simulation requests to Kafka. This is how it runs under docker compose and on EKS.
"""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from aegis.config import REPO_ROOT, Settings, get_settings
from aegis.graph.analysis import graph_context
from aegis.investigator.context import compact_event
from aegis.observability import metrics
from aegis.rules import load_rules
from aegis.simulator import DESCRIPTIONS, SCENARIOS

log = logging.getLogger(__name__)
STATIC = Path(__file__).resolve().parent.parent / "dashboard" / "static"
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class StatusUpdate(BaseModel):
    status: str


def create_app(pipeline=None, settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="Aegis", version="0.1.0",
                  description="AI-powered cloud security detection and investigation platform (lab)")
    token = os.environ.get("AEGIS_API_TOKEN")

    if pipeline is not None:
        repo = pipeline.repo
        investigator = pipeline.investigator
        bus = None
    else:
        from aegis.bus import create_bus
        from aegis.investigator import Investigator
        from aegis.storage.db import create_repository

        repo = create_repository(settings.database_url)
        investigator = Investigator(repo, settings)
        bus = create_bus(settings)

    def auth(authorization: str | None = Header(default=None)) -> None:
        # Optional bearer token. A real deployment would sit behind an identity-aware
        # proxy / OIDC (zero trust) - see README "Security of Aegis itself".
        if token and authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")

    api = Depends(auth)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        repo.stats()  # touches the database
        return {"status": "ready"}

    @app.get("/metrics")
    def prom():
        for level in LEVELS:
            metrics.OPEN_INCIDENTS.labels(level).set(repo.stats()["open_incidents_by_level"].get(level, 0))
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/api/stats", dependencies=[api])
    def stats():
        s = repo.stats()
        s["mode"] = "local" if pipeline is not None else "remote"
        has_creds = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
        wants_llm = pipeline.use_llm if pipeline is not None else True
        s["llm"] = {"enabled": bool(settings.llm_enabled and has_creds and wants_llm), "model": settings.llm_model}
        s["ml_model"] = settings.ml_model
        return s

    @app.get("/api/incidents", dependencies=[api])
    def incidents(min_level: str = Query("LOW"), status: str | None = None, limit: int = 100):
        floor = LEVELS.index(min_level.upper()) if min_level.upper() in LEVELS else 0
        out = []
        for inc in repo.list_incidents(limit=500, status=status):
            if LEVELS.index(inc.risk_level) >= floor:
                d = inc.model_dump(mode="json")
                d["alert_count"] = len(inc.alert_ids)
                rep = repo.latest_report(inc.incident_id)
                d["has_report"] = rep is not None
                out.append(d)
        return out[:limit]

    @app.get("/api/incidents/{incident_id}", dependencies=[api])
    def incident(incident_id: int):
        inc = repo.get_incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        alerts = repo.get_alerts(inc.alert_ids)
        ids: list[str] = []
        for a in alerts:
            ids += [e for e in a.event_ids if e not in ids]
        events = repo.get_events(ids[:300])
        rep = repo.latest_report(incident_id)
        return {
            "incident": inc.model_dump(mode="json"),
            "alerts": [a.model_dump(mode="json") for a in alerts],
            "timeline": [compact_event(e) for e in events],
            "graph": graph_context(repo, inc),
            "report": rep[0].model_dump(mode="json") if rep else None,
        }

    @app.post("/api/incidents/{incident_id}/investigate", dependencies=[api])
    def investigate(incident_id: int, llm: bool = True):
        inc = repo.get_incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        lock = pipeline.lock if pipeline is not None else threading.Lock()
        with lock:
            report = investigator.investigate(inc, use_llm=llm)
        return report.model_dump(mode="json")

    @app.post("/api/incidents/{incident_id}/status", dependencies=[api])
    def set_status(incident_id: int, body: StatusUpdate):
        inc = repo.get_incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        if body.status not in ("open", "investigating", "closed"):
            raise HTTPException(400, "status must be open|investigating|closed")
        inc.status = body.status
        repo.save_incident(inc)
        return {"incident_id": incident_id, "status": inc.status}

    @app.get("/api/alerts", dependencies=[api])
    def alerts(limit: int = 200):
        return [{**a.model_dump(mode="json"), "incident_id": i} for a, i in repo.list_alerts(limit=limit)]

    @app.get("/api/events", dependencies=[api])
    def events(limit: int = 100):
        return [compact_event(e) for e in repo.recent_events(limit)]

    @app.get("/api/scenarios", dependencies=[api])
    def scenarios():
        return [{"name": n, "description": DESCRIPTIONS[n]} for n in SCENARIOS]

    @app.post("/api/simulate/{scenario}", dependencies=[api])
    def simulate(scenario: str):
        if scenario not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario; choose from {sorted(SCENARIOS)}")
        seed = random.randint(0, 10**6)
        if pipeline is not None:
            n = pipeline.simulate(scenario, start=datetime.now(UTC), seed=seed)
            return {"scenario": scenario, "processed_messages": n}
        from aegis.bus.base import RAW_TOPICS
        from aegis.simulator import run_scenario

        envs = run_scenario(scenario, datetime.now(UTC), seed=seed)
        for env in envs:
            bus.publish(RAW_TOPICS[env["source"]], env)
        bus.flush()
        return {"scenario": scenario, "published_records": len(envs)}

    @app.get("/api/rules", dependencies=[api])
    def rules():
        return [{"id": r.id, "name": r.name, "severity": r.severity.value, "type": r.type, "analyzer": r.analyzer,
                 "mitre": r.mitre.model_dump() if r.mitre else None, "description": r.description}
                for r in load_rules(settings.rules_dir)]

    @app.get("/api/ml/report", dependencies=[api])
    def ml_report():
        for p in (settings.report_dir / "metrics.json", REPO_ROOT / "ml" / "reports" / "metrics.json",
                  settings.model_dir / "reports" / "metrics.json"):
            if p.exists():
                return JSONResponse(json.loads(p.read_text()))
        raise HTTPException(404, "no ML report yet - run `aegis train`")

    if STATIC.exists():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/")
        def index():
            return FileResponse(STATIC / "index.html")

    return app


class LiveFeeder(threading.Thread):
    """Local mode only: keep benign traffic flowing so the dashboard looks alive."""

    def __init__(self, pipeline, activities_per_tick: int = 3, interval: float = 2.0, attack_every_s: float = 0):
        super().__init__(daemon=True)
        from aegis.simulator import BaselineSimulator

        self.pipeline, self.n, self.interval = pipeline, activities_per_tick, interval
        self.sim = BaselineSimulator(int(time.time()))
        self.attack_every = attack_every_s
        self.next_attack = time.time() + attack_every_s if attack_every_s else None

    def run(self) -> None:
        import heapq

        from aegis.simulator import event_time

        heap: list[tuple[float, int, dict]] = []
        seq = 0
        while True:
            now = datetime.now(UTC)
            for _ in range(self.n):
                for env in self.sim.random_activity(now):
                    seq += 1
                    heapq.heappush(heap, (event_time(env).timestamp(), seq, env))
            due = []
            while heap and heap[0][0] <= now.timestamp():
                due.append(heapq.heappop(heap)[2])
            try:
                self.pipeline.process(due)
                if self.next_attack and time.time() >= self.next_attack:
                    self.pipeline.simulate(random.choice(list(SCENARIOS)), start=now)
                    self.next_attack = time.time() + self.attack_every
            except Exception:
                log.exception("live feeder failed")
            time.sleep(self.interval)


def app_from_env() -> FastAPI:
    """Entry point for `uvicorn aegis.api:app_from_env --factory` (remote mode)."""
    return create_app()
