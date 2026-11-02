from collections import Counter
from datetime import timedelta

import pytest

from aegis.collectors import normalize
from aegis.config import get_settings
from aegis.rules import Rule, RulesEngine, evaluate, load_rules
from aegis.schema import Event
from aegis.simulator import SCENARIOS, build_dataset, run_scenario
from tests.conftest import START


def _evt(**kw):
    base = dict(event_id="e1", timestamp=START, source="auth", category="authentication", action="login",
                outcome="failure", principal="alice", src_ip="203.0.113.5")
    base.update(kw)
    return Event(**base)


def test_condition_operators():
    e = _evt(attributes={"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess", "n": 5})
    assert evaluate({"field": "attributes.policy_arn", "contains": "Administrator"}, e)
    assert evaluate({"field": "src_ip", "cidr": "203.0.113.0/24"}, e)
    assert evaluate({"not": {"field": "src_ip", "cidr": "10.0.0.0/8"}}, e)
    assert evaluate({"any": [{"field": "outcome", "eq": "success"}, {"field": "attributes.n", "gte": 5}]}, e)
    assert not evaluate({"all": [{"field": "outcome", "eq": "failure"}, {"field": "principal", "in": ["bob"]}]}, e)
    with pytest.raises(ValueError):
        evaluate({"field": "x", "bogus": 1}, e)


def test_threshold_rule_fires_once_with_cooldown():
    rule = Rule.from_dict({
        "id": "T-1", "name": "t", "severity": "medium", "analyzer": "auth", "type": "threshold",
        "match": [{"field": "outcome", "eq": "failure"}],
        "threshold": {"count": 3, "window": 60, "group_by": ["principal"]},
    })
    eng = RulesEngine([rule])
    fired = [eng.process(_evt(event_id=f"e{i}", timestamp=START + timedelta(seconds=i))) for i in range(6)]
    assert [len(f) for f in fired] == [0, 0, 1, 0, 0, 0]
    assert len(fired[2][0].event_ids) == 3


def test_distinct_threshold_password_spray():
    rule = next(r for r in load_rules(get_settings().rules_dir) if r.id == "AEG-AUTH-002")
    eng = RulesEngine([rule])
    alerts = [a for env in run_scenario("password_spray", START, seed=2) for a in eng.process(normalize(env))]
    assert len(alerts) == 1 and len(alerts[0].evidence["distinct_values"]) >= 8


def test_sequence_rule_failures_then_success():
    eng = RulesEngine(load_rules(get_settings().rules_dir, analyzer="auth"))
    evs = [normalize(e) for e in run_scenario("credential_compromise", START, seed=3)]
    fired = Counter(a.rule_id for e in evs for a in eng.process(e))
    assert fired["AEG-AUTH-003"] == 1
    assert fired["AEG-AUTH-006"] >= 1


def test_cooldown_is_event_time_based_and_tolerates_out_of_order():
    from aegis.state import MemoryStateStore

    st = MemoryStateStore()
    assert st.cooldown("k", 10_000, 600)       # fires
    assert not st.cooldown("k", 10_300, 600)   # suppressed: 5 min later
    assert st.cooldown("k", 9_000, 600)        # an *older* event outside the window still fires
    assert not st.cooldown("k", 9_100, 600)


def test_every_rule_file_loads_and_embedded_tests_pass():
    rules = load_rules(get_settings().rules_dir)
    assert len(rules) >= 20
    for rule in rules:
        assert rule.mitre is not None, rule.id
        for t in rule.tests:
            eng = RulesEngine([rule])
            hits = [a for env in run_scenario(t["scenario"], START, seed=1) for a in eng.process(normalize(env))]
            assert hits, f"{rule.id} did not fire on {t['scenario']}"


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_every_scenario_is_detected_by_rules(scenario):
    eng = RulesEngine(load_rules(get_settings().rules_dir))
    # give the new_value rules some history first
    for env in build_dataset(1, seed=5, start=START - timedelta(days=1, hours=1)):
        eng.process(normalize(env))
    alerts = [a for env in run_scenario(scenario, START, seed=9) for a in eng.process(normalize(env))]
    assert alerts, scenario


def test_benign_false_positive_budget():
    eng = RulesEngine(load_rules(get_settings().rules_dir))
    alerts = [a for env in build_dataset(3, seed=21) for a in eng.process(normalize(env))]
    # ~40k benign events over 3 days should produce only a handful of (low/medium) alerts
    assert len(alerts) <= 12
    assert not any(a.severity.value == "critical" for a in alerts)
