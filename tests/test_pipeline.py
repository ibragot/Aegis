"""End-to-end: synthetic logs -> collectors -> rules + ML -> correlator -> graph -> investigator."""

from datetime import timedelta

from aegis.graph.analysis import export_cypher, graph_context
from tests.conftest import START


def test_flagship_scenario_becomes_one_critical_incident(pipeline):
    pipeline.simulate("credential_compromise", start=START, seed=3, with_baseline_minutes=15)
    incidents = pipeline.repo.list_incidents()
    top = incidents[0]
    assert top.risk_level == "CRITICAL"
    ids = {e.id for e in top.entities}
    assert "service_account:service-account-17" in ids
    # the exfiltration flow comes from the *new instance's* IP - only linkable through the graph
    alerts = pipeline.repo.get_alerts(top.alert_ids)
    rules = {a.rule_id for a in alerts}
    assert {"AEG-AUTH-006", "AEG-IAM-001", "AEG-RES-001", "AEG-NET-002"} <= rules
    assert top.tactics[0] == "Initial Access" and "Exfiltration" in top.tactics
    # score is fully explained by its factors
    assert abs(sum(f.points for f in top.score_breakdown) - top.risk_score) < 1e-6 or top.risk_score == 100
    # benign background produced at most low-risk noise
    assert all(i.risk_level in ("LOW", "MEDIUM") for i in incidents[1:])


def test_graph_analysis_finds_pivot_path_and_blast_radius(pipeline):
    pipeline.simulate("credential_compromise", start=START, seed=3)
    top = pipeline.repo.list_incidents()[0]
    g = graph_context(pipeline.repo, top)
    assert g["pivot"] == "service_account:service-account-17"
    assert any(p[0].startswith("ip:203.0.113.") for p in g["attack_paths"])
    relations = {b["relation"] for b in g["blast_radius"]}
    assert "created" in relations
    assert "MERGE" in export_cypher(pipeline.repo)


def test_report_is_generated_for_high_risk_incident(pipeline):
    pipeline.simulate("defense_evasion", start=START, seed=4)
    top = pipeline.repo.list_incidents()[0]
    report, n = pipeline.repo.latest_report(top.incident_id)
    assert report.generated_by == "template"
    assert report.recommended_actions[0].priority == "immediate"
    assert any("defense-evasion" in ref for ref in report.references)


def test_separate_attacks_stay_separate_incidents(pipeline):
    pipeline.simulate("password_spray", start=START, seed=1)
    pipeline.simulate("defense_evasion", start=START + timedelta(hours=3), seed=2)
    high = [i for i in pipeline.repo.list_incidents() if i.risk_level in ("HIGH", "CRITICAL")]
    assert len(high) == 2
    titles = " ".join(i.title for i in high)
    assert "frank" in titles and "carol" in titles
