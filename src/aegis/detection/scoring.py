"""Incident risk scoring - transparent and explainable on purpose.

Every point added to the score is recorded as a `ScoreFactor` with a
human-readable reason. Analysts (and the AI investigator) can see exactly why
an incident is CRITICAL, and detection engineers can tune the weights.
"""

from __future__ import annotations

from aegis.enrichment import asset_criticality, geoip
from aegis.schema import SEVERITY_WEIGHT, Alert, EntityRef, ScoreFactor

# MITRE ATT&CK enterprise tactics in kill-chain order
KILL_CHAIN = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]
STAGE = {t: i for i, t in enumerate(KILL_CHAIN)}


def risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def ordered_tactics(alerts: list[Alert]) -> list[str]:
    seen: list[str] = []
    for a in sorted(alerts, key=lambda a: a.event_time):
        if a.mitre and a.mitre.tactic not in seen:
            seen.append(a.mitre.tactic)
    return seen


def score_incident(alerts: list[Alert], entities: list[EntityRef]) -> tuple[float, list[ScoreFactor]]:
    factors: list[ScoreFactor] = []
    if not alerts:
        return 0.0, factors

    top = max(alerts, key=lambda a: SEVERITY_WEIGHT[a.severity])
    factors.append(ScoreFactor(factor="max_severity", points=SEVERITY_WEIGHT[top.severity],
                               reason=f"highest alert severity is {top.severity.value} ({top.rule_name})"))

    tactics = ordered_tactics(alerts)
    if len(tactics) > 1:
        factors.append(ScoreFactor(factor="tactic_breadth", points=min(8 * (len(tactics) - 1), 30),
                                   reason=f"{len(tactics)} ATT&CK tactics observed: {' -> '.join(tactics)}"))
    if len(tactics) >= 3:
        stages = [STAGE.get(t, 0) for t in tactics]
        forward = sum(1 for a, b in zip(stages, stages[1:], strict=False) if b > a)
        if forward / (len(stages) - 1) >= 0.5:
            factors.append(ScoreFactor(factor="kill_chain_progression", points=10,
                                       reason="tactics appear in kill-chain order (access -> escalation -> impact)"))

    extra = alerts.copy()
    extra.remove(top)
    if extra:
        pts = min(sum(3 if a.severity.value in ("high", "critical") else 1 for a in extra), 10)
        factors.append(ScoreFactor(factor="alert_volume", points=pts, reason=f"{len(extra)} additional correlated alerts"))

    detectors = {a.detector for a in alerts}
    if detectors == {"rules", "ml"}:
        factors.append(ScoreFactor(factor="ml_corroboration", points=7,
                                   reason="the behavioral ML model independently flagged the same entities"))
    elif detectors == {"ml"}:
        best = max(a.score for a in alerts)
        factors.append(ScoreFactor(factor="ml_only", points=round(10 * best, 1),
                                   reason="only the ML anomaly detector fired (no signature match)"))

    crit = {asset_criticality(e.value) for e in entities if e.type in ("resource", "role")}
    if "critical" in crit:
        factors.append(ScoreFactor(factor="asset_criticality", points=10, reason="a critical production asset is involved"))
    elif "high" in crit:
        factors.append(ScoreFactor(factor="asset_criticality", points=5, reason="a high-value asset is involved"))

    if any(e.type == "ip" and geoip(e.value).is_hosting for e in entities):
        factors.append(ScoreFactor(factor="hosting_provider_ip", points=5,
                                   reason="activity originates from a hosting-provider / VPS address"))

    score = min(sum(f.points for f in factors), 100.0)
    return round(score, 1), factors
