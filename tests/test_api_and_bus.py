from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.bus.memory import MemoryBus
from aegis.storage.archive import Archiver
from tests.conftest import START


def test_memory_bus_consumer_groups_and_commit():
    bus = MemoryBus()
    for i in range(5):
        bus.publish("t", {"i": i})
    a1 = bus.consumer(["t"], "group-a")
    b = bus.consumer(["t"], "group-b")
    assert len(a1.poll(max_messages=3)) == 3
    a1.commit()
    a2 = bus.consumer(["t"], "group-a")  # a new member of the same group resumes from the committed offset
    assert [m.value["i"] for m in a2.poll()] == [3, 4]
    assert len(b.poll()) == 5  # independent group sees everything


def test_archiver_writes_partitioned_gzip(settings):
    from aegis.simulator import run_scenario

    arch = Archiver(settings)
    for env in run_scenario("defense_evasion", START, seed=1):
        arch.add(env)
    arch.flush()
    files = list(settings.archive_dir.rglob("*.jsonl.gz"))
    assert files and any("source=cloudtrail/dt=2026-09-14/hour=14" in str(f) for f in files)


def test_api_endpoints(pipeline, settings):
    pipeline.simulate("credential_compromise", start=START, seed=3)
    client = TestClient(create_app(pipeline, settings))
    assert client.get("/healthz").json() == {"status": "ok"}
    stats = client.get("/api/stats").json()
    assert stats["events"] > 0 and stats["mode"] == "local"
    incs = client.get("/api/incidents?min_level=HIGH").json()
    assert incs and incs[0]["risk_level"] == "CRITICAL"
    detail = client.get(f"/api/incidents/{incs[0]['incident_id']}").json()
    assert detail["graph"]["nodes"] and detail["timeline"] and detail["report"]
    rep = client.post(f"/api/incidents/{incs[0]['incident_id']}/investigate?llm=false").json()
    assert rep["generated_by"] == "template"
    assert client.post("/api/simulate/k8s_compromise").status_code == 200
    assert client.post("/api/simulate/not_a_scenario").status_code == 404
    assert len(client.get("/api/rules").json()) >= 20
    assert "aegis_alerts_total" in client.get("/metrics").text
    assert client.get("/").status_code == 200


def test_api_token(pipeline, settings, monkeypatch):
    monkeypatch.setenv("AEGIS_API_TOKEN", "s3cret")
    client = TestClient(create_app(pipeline, settings))
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.get("/healthz").status_code == 200  # probes stay unauthenticated
