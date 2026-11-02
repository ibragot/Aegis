"""Detection engine: correlate individual alerts into incidents.

Individually, "a login from a new country" or "a role got a policy attached"
are weak signals; dozens fire every day. The correlator groups alerts that
share *strong* entities (an identity, an access key, an external IP, an
instance) within a time window - or that are linked through causal edges in
the entity graph (user --created--> instance --has_ip--> ip) - into one
incident with an explainable risk score. That is the step that turns a noisy
alert stream into a short, prioritized queue for a human analyst.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from aegis.detection.scoring import ordered_tactics, risk_level, score_incident
from aegis.entities import is_strong
from aegis.graph.analysis import expand_strong
from aegis.observability import metrics
from aegis.schema import Alert, EntityRef, Incident, utcnow
from aegis.storage.db import Repository

log = logging.getLogger(__name__)


def _title(incident: Incident, alerts: list[Alert]) -> str:
    tactics = incident.tactics
    if len(tactics) > 3:
        tactics = [tactics[0], tactics[len(tactics) // 2], tactics[-1]]
    # Name the incident after the identity that *acted* most often (successful actions only -
    # the targets of failed logins are victims, not actors), else after the source IP.
    from collections import Counter

    actors: Counter = Counter()
    for a in alerts:
        if a.evidence.get("outcome") != "failure":
            for e in a.entities:
                if e.type in ("user", "service_account"):
                    actors[e.value] += 1
    who = actors.most_common(1)[0][0] if actors else None
    who = who or next((e.value for e in incident.entities if e.type in ("ip", "host")), "unknown entity")
    if not tactics:
        top = max(alerts, key=lambda a: a.score)
        return f"{top.rule_name}: {who}"
    return f"{' -> '.join(tactics)} involving {who}"


class Correlator:
    def __init__(self, repo: Repository, window_minutes: int = 60):
        self.repo = repo
        self.window = timedelta(minutes=window_minutes)

    @staticmethod
    def correlation_keys(alert: Alert) -> list[str]:
        """Strong entities usable for merging.

        On a *failed* authentication the principal is the attack's target, not
        its actor: a password spray "touches" every user it tries, and those
        users must not glue unrelated incidents together.
        """
        failed = alert.evidence.get("outcome") == "failure" and alert.evidence.get("category") == "authentication"
        return [e.id for e in alert.entities
                if is_strong(e) and not (failed and e.type in ("user", "service_account"))]

    def process(self, alert: Alert) -> Incident:
        strong = self.correlation_keys(alert)
        linked = expand_strong(self.repo, strong, hops=1) if strong else set()
        since = alert.event_time - self.window
        candidates = [
            inc for inc in self.repo.open_incidents_since(since)
            if set(inc.correlation_keys) & (linked or set(strong))
        ]
        candidates.sort(key=lambda i: i.incident_id)

        if not candidates:
            inc = Incident(incident_id=self.repo.next_incident_id(), title="", risk_score=0, risk_level="LOW",
                           first_seen=alert.event_time, last_seen=alert.event_time)
            created = True
        else:
            inc, others = candidates[0], candidates[1:]
            created = False
            for other in others:  # the new alert bridges several incidents -> merge them
                log.info("merging incident %s into %s", other.incident_id, inc.incident_id)
                inc.alert_ids += [a for a in other.alert_ids if a not in inc.alert_ids]
                inc.entities = _union(inc.entities, other.entities)
                inc.correlation_keys = sorted(set(inc.correlation_keys) | set(other.correlation_keys))
                inc.first_seen = min(inc.first_seen, other.first_seen)
                inc.last_seen = max(inc.last_seen, other.last_seen)
            if others:
                self.repo.reassign_alerts([o.incident_id for o in others], inc.incident_id)
                self.repo.delete_incidents([o.incident_id for o in others])

        if alert.alert_id not in inc.alert_ids:
            inc.alert_ids.append(alert.alert_id)
        inc.entities = _union(inc.entities, alert.entities)
        inc.correlation_keys = sorted(set(inc.correlation_keys) | set(strong))
        inc.first_seen = min(inc.first_seen, alert.event_time)
        inc.last_seen = max(inc.last_seen, alert.event_time)

        self.repo.save_alert(alert, incident_id=inc.incident_id)
        self._rescore_and_save(inc)
        if created:
            metrics.INCIDENTS.labels(inc.risk_level).inc()
        else:
            metrics.INCIDENT_UPDATES.inc()
        return inc

    def _rescore_and_save(self, inc: Incident) -> None:
        alerts = self.repo.get_alerts(inc.alert_ids)
        inc.tactics = ordered_tactics(alerts)
        inc.risk_score, inc.score_breakdown = score_incident(alerts, inc.entities)
        inc.risk_level = risk_level(inc.risk_score)
        inc.title = _title(inc, alerts)
        inc.updated_at = utcnow()
        self.repo.save_incident(inc)

    def reconcile(self) -> list[Incident]:
        """Periodic merge pass for *late-arriving data*.

        In a distributed pipeline the alert about an exfiltration flow from
        10.0.9.77 can reach the correlator before the indexer has stored the
        `instance --has_ip--> 10.0.9.77` edge that links it to the attacker's
        session. Re-checking open incidents every few seconds fixes that.
        """
        open_incs = self.repo.list_incidents(limit=300, status="open")
        if len(open_incs) < 2:
            return []
        horizon = max(i.last_seen for i in open_incs) - 6 * self.window
        incs = sorted((i for i in open_incs if i.last_seen >= horizon), key=lambda i: i.incident_id)
        strong = {i.incident_id: set(i.correlation_keys) for i in incs}
        expanded = {i.incident_id: expand_strong(self.repo, sorted(strong[i.incident_id])) for i in incs}
        parent = {i.incident_id: i.incident_id for i in incs}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for a_i, a in enumerate(incs):
            for b in incs[a_i + 1 :]:
                close = (b.first_seen - a.last_seen) <= self.window and (a.first_seen - b.last_seen) <= self.window
                if close and (expanded[a.incident_id] & strong[b.incident_id]
                              or expanded[b.incident_id] & strong[a.incident_id]):
                    parent[find(b.incident_id)] = find(a.incident_id)
        groups: dict[int, list[Incident]] = {}
        for inc in incs:
            groups.setdefault(find(inc.incident_id), []).append(inc)
        changed = []
        for root, members in groups.items():
            if len(members) < 2:
                continue
            target = next(m for m in members if m.incident_id == root)
            others = [m for m in members if m is not target]
            for o in others:
                target.alert_ids += [a for a in o.alert_ids if a not in target.alert_ids]
                target.entities = _union(target.entities, o.entities)
                target.correlation_keys = sorted(set(target.correlation_keys) | set(o.correlation_keys))
                target.first_seen = min(target.first_seen, o.first_seen)
                target.last_seen = max(target.last_seen, o.last_seen)
            log.info("reconcile: merged %s into %s", [o.incident_id for o in others], target.incident_id)
            self.repo.reassign_alerts([o.incident_id for o in others], target.incident_id)
            self.repo.delete_incidents([o.incident_id for o in others])
            self._rescore_and_save(target)
            changed.append(target)
        return changed


def _union(a: list[EntityRef], b: list[EntityRef]) -> list[EntityRef]:
    seen = {e.id for e in a}
    out = list(a)
    for e in b:
        if e.id not in seen:
            seen.add(e.id)
            out.append(e)
    return out
