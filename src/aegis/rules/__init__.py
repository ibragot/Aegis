"""A small, Sigma-inspired detection rules engine.

Rules are YAML files in `config/rules/` (detection-as-code: version-controlled,
reviewed in pull requests, unit-tested). Four rule types are supported:

* `match`      - stateless: alert when a single event matches the conditions
* `threshold`  - N matching events (or N *distinct* values) within a window, per group
* `new_value`  - a field takes a value never seen before for this group
                 (e.g. first login from a new country for this user)
* `sequence`   - ordered steps within a window (e.g. >=3 failures, then success)

Condition syntax::

    match:
      all:
        - {field: category, eq: authentication}
        - {field: outcome, eq: failure}
        - any:
            - {field: attributes.policy_arn, contains: AdministratorAccess}
            - not: {field: src_ip, cidr: 10.0.0.0/8}
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis.entities import _get, entities_from_event
from aegis.schema import Alert, Event, Mitre, Severity
from aegis.state import MemoryStateStore, StateStore

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------- conditions
def _cidr(value: Any, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(str(value)) in ipaddress.ip_network(cidr)
    except ValueError:
        return False


_OPS = {
    "eq": lambda v, x: v == x,
    "neq": lambda v, x: v != x,
    "in": lambda v, x: v in x,
    "not_in": lambda v, x: v not in x,
    "contains": lambda v, x: v is not None and str(x) in str(v),
    "icontains": lambda v, x: v is not None and str(x).lower() in str(v).lower(),
    "startswith": lambda v, x: v is not None and str(v).startswith(tuple(x) if isinstance(x, list) else x),
    "endswith": lambda v, x: v is not None and str(v).endswith(x),
    "regex": lambda v, x: v is not None and re.search(x, str(v)) is not None,
    "gt": lambda v, x: v is not None and v > x,
    "gte": lambda v, x: v is not None and v >= x,
    "lt": lambda v, x: v is not None and v < x,
    "lte": lambda v, x: v is not None and v <= x,
    "exists": lambda v, x: (v is not None) == bool(x),
    "cidr": lambda v, x: v is not None and _cidr(v, x),
}


def evaluate(cond: dict | list, evt: Event) -> bool:
    if isinstance(cond, list):
        return all(evaluate(c, evt) for c in cond)
    if "all" in cond:
        return all(evaluate(c, evt) for c in cond["all"])
    if "any" in cond:
        return any(evaluate(c, evt) for c in cond["any"])
    if "not" in cond:
        return not evaluate(cond["not"], evt)
    value = _get(evt, cond["field"])
    for op, arg in cond.items():
        if op == "field":
            continue
        if op not in _OPS:
            raise ValueError(f"unknown operator {op!r}")
        if not _OPS[op](value, arg):
            return False
    return True


# ----------------------------------------------------------------------------- rule model
@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: Severity
    analyzer: str
    type: str
    match: Any
    mitre: Mitre | None
    entities: list[str] = field(default_factory=lambda: ["principal", "src_ip", "target_resource"])
    threshold: dict | None = None
    new_value: dict | None = None
    sequence: dict | None = None
    cooldown: float = 0
    enabled: bool = True
    tests: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Rule:
        return cls(
            id=d["id"],
            name=d["name"],
            description=d.get("description", "").strip(),
            severity=Severity(d["severity"]),
            analyzer=d["analyzer"],
            type=d.get("type", "match"),
            match=d.get("match", []),
            mitre=Mitre(**d["mitre"]) if d.get("mitre") else None,
            entities=d.get("entities", ["principal", "src_ip", "target_resource"]),
            threshold=d.get("threshold"),
            new_value=d.get("new_value"),
            sequence=d.get("sequence"),
            cooldown=float(d.get("cooldown", 600 if d.get("type") in ("threshold", "sequence") else 0)),
            enabled=d.get("enabled", True),
            tests=d.get("tests", []),
        )


def load_rules(rules_dir: Path, analyzer: str | None = None) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        docs = yaml.safe_load(path.read_text()) or []
        for d in docs if isinstance(docs, list) else [docs]:
            rule = Rule.from_dict(d)
            if rule.enabled and (analyzer is None or rule.analyzer == analyzer):
                rules.append(rule)
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


# ----------------------------------------------------------------------------- engine
class RulesEngine:
    def __init__(self, rules: list[Rule], state: StateStore | None = None):
        self.rules = rules
        self.state = state or MemoryStateStore()

    def _group(self, evt: Event, keys: list[str]) -> str:
        return "|".join(str(_get(evt, k)) for k in keys)

    def _alert(self, rule: Rule, evt: Event, event_ids: list[str], evidence: dict) -> Alert:
        return Alert(
            event_time=evt.timestamp,
            detector="rules",
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            score={"low": 0.3, "medium": 0.5, "high": 0.75, "critical": 0.95}[rule.severity.value],
            mitre=rule.mitre,
            description=rule.description,
            entities=entities_from_event(evt, rule.entities),
            event_ids=event_ids[-50:],
            evidence={"action": evt.action, "src_ip": evt.src_ip, "principal": evt.principal,
                      "target": evt.target_resource, **evidence},
        )

    def _cooldown_ok(self, rule: Rule, group: str, ts: float) -> bool:
        if rule.cooldown <= 0:
            return True
        return self.state.cooldown(f"{rule.id}:{group}", ts, rule.cooldown)

    def process(self, evt: Event) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            try:
                alert = self._apply(rule, evt)
            except Exception:  # one bad rule must not stop the others
                log.exception("rule %s failed", rule.id)
                continue
            if alert:
                alerts.append(alert)
        return alerts

    def _apply(self, rule: Rule, evt: Event) -> Alert | None:
        ts = evt.timestamp.timestamp()
        if rule.type == "match":
            if evaluate(rule.match, evt):
                # Optional de-duplication: one alert per (principal, source IP) per cooldown period.
                if not self._cooldown_ok(rule, self._group(evt, ["principal", "src_ip"]), ts):
                    return None
                return self._alert(rule, evt, [evt.event_id], {})
            return None

        if rule.type == "threshold":
            if not evaluate(rule.match, evt):
                return None
            th = rule.threshold or {}
            window = float(th.get("window", 300))
            group = self._group(evt, th.get("group_by", ["principal"]))
            key = f"{rule.id}:{group}"
            self.state.window_add(key + ":ev", ts, evt.event_id, window)
            if th.get("distinct"):
                value = _get(evt, th["distinct"])
                self.state.window_add(key + ":dv", ts, str(value), window)
                n = self.state.window_count(key + ":dv", ts - window)
            else:
                n = self.state.window_count(key + ":ev", ts - window)
            if n >= int(th.get("count", 5)) and self._cooldown_ok(rule, group, ts):
                ids = self.state.window_members(key + ":ev", ts - window)
                ev = {"count": n, "window_seconds": window, "group": group}
                if th.get("distinct"):
                    ev["distinct_values"] = self.state.window_members(key + ":dv", ts - window)[:25]
                return self._alert(rule, evt, ids, ev)
            return None

        if rule.type == "new_value":
            if not evaluate(rule.match, evt):
                return None
            nv = rule.new_value or {}
            value = _get(evt, nv["field"])
            if value in (None, ""):
                return None
            group = self._group(evt, nv.get("group_by", ["principal"]))
            key = f"{rule.id}:{group}"
            known = self.state.seen_size(key)
            is_new = self.state.seen_add(key, str(value))
            # Only alert once the group has a history - the very first value is "learning".
            if is_new and known >= int(nv.get("min_known", 1)):
                return self._alert(rule, evt, [evt.event_id], {"new_value": value, "field": nv["field"],
                                                               "known_values": known})
            return None

        if rule.type == "sequence":
            seq = rule.sequence or {}
            window = float(seq.get("window", 600))
            group = self._group(evt, seq.get("group_by", ["principal"]))
            steps = seq["steps"]
            fired = None
            for i, step in enumerate(steps):
                if not evaluate(step["match"], evt):
                    continue
                key = f"{rule.id}:{group}:s{i}"
                if i == len(steps) - 1:
                    ok = all(
                        self.state.window_count(f"{rule.id}:{group}:s{j}", ts - window) >= int(s.get("min_count", 1))
                        for j, s in enumerate(steps[:-1])
                    )
                    if ok and self._cooldown_ok(rule, group, ts):
                        ids = []
                        for j in range(len(steps) - 1):
                            ids += self.state.window_members(f"{rule.id}:{group}:s{j}", ts - window)
                        fired = self._alert(rule, evt, ids + [evt.event_id],
                                            {"steps": [s.get("name", f"step{j}") for j, s in enumerate(steps)]})
                self.state.window_add(key, ts, evt.event_id, window)
            return fired

        raise ValueError(f"unknown rule type {rule.type}")
