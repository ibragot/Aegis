"""Online feature extraction - the heart of behavioural anomaly detection.

Each event is turned into a fixed-length numeric vector that describes *how
unusual this event is for this identity*, using a per-identity profile that is
updated as events stream in (login hours, countries, IPs, actions, rates...).

Training/serving parity: the exact same `FeatureExtractor` class is used when
building the training set offline (`aegis train`) and inside the
`ml-inference` Kafka consumer. Computing features differently in the two
places ("training/serving skew") is one of the most common ML production bugs.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

from aegis.schema import Event

SENSITIVE_ACTIONS = {
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreateUser", "CreateAccessKey",
    "CreateLoginProfile", "StopLogging", "DeleteTrail", "DeleteFlowLogs", "DeleteDetector", "GetSecretValue",
    "ListSecrets", "RunInstances", "AssumeRole", "create clusterrolebindings", "create pods/exec",
    "GetAccountAuthorizationDetails",
}
CATEGORIES = ["authentication", "iam", "resource", "api", "kubernetes", "network", "application"]

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "is_weekend",
    "hour_rarity",  # how unusual this hour is for the identity (0 = typical, 1 = never seen)
    "new_country", "new_ip", "new_action", "new_resource",
    "action_rarity",  # -log P(action | identity), smoothed
    "global_action_rarity",  # -log P(action) across everyone
    "transition_rarity",  # -log P(action | previous action of this identity) - a first-order Markov model
    "rate_5m",  # events by this identity in the last 5 minutes (log1p)
    "rate_ratio",  # current 5-minute rate / identity's typical rate
    "failures_10m", "distinct_ips_1h", "distinct_resources_10m", "distinct_ports_2m",
    "is_failure", "is_privileged", "is_sensitive_action", "mfa_missing", "src_hosting", "src_external",
    "log_bytes_out", "bytes_zscore",
    *[f"cat_{c}" for c in CATEGORIES],
]


@dataclass
class Profile:
    """Everything we remember about one identity."""

    n: int = 0
    hours: Counter = field(default_factory=Counter)
    countries: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    actions: Counter = field(default_factory=Counter)
    resources: set = field(default_factory=set)
    transitions: Counter = field(default_factory=Counter)
    last_action: str | None = None
    recent: deque = field(default_factory=lambda: deque(maxlen=400))  # (ts, ip, resource, failure, port)
    bytes_mean: float = 0.0
    bytes_m2: float = 0.0  # for Welford's online variance
    bytes_n: int = 0
    active_hours: int = 0  # number of distinct clock-hours in which this identity was active
    last_hour: int | None = None


class FeatureExtractor:
    def __init__(self) -> None:
        self.profiles: dict[str, Profile] = defaultdict(Profile)
        self.global_actions: Counter = Counter()
        self.global_n = 0

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _rarity(count: int, total: int, vocab: int) -> float:
        # Laplace-smoothed negative log probability, normalized to roughly 0..1
        p = (count + 1) / (total + vocab + 1)
        return min(-math.log(p) / 10.0, 1.5)

    def transform(self, evt: Event, update: bool = True) -> np.ndarray:
        """Compute the feature vector for `evt` *before* it updates the profile."""
        p = self.profiles[evt.entity_key]
        ts = evt.timestamp.timestamp()
        hour = evt.timestamp.hour
        action = evt.action

        # 0 <= delta guards against out-of-order events counting as "recent"
        recent = [r for r in p.recent if 0 <= ts - r[0] <= 3600]
        last_5m = [r for r in recent if ts - r[0] <= 300]
        last_10m = [r for r in recent if ts - r[0] <= 600]
        last_2m = [r for r in recent if ts - r[0] <= 120]

        # Typical rate *while active*. (An earlier version divided by the identity's whole
        # lifetime, which silently broke in production: a gap between the training data
        # and live traffic made every identity look 100x busier than normal - a real
        # training/serving-skew bug caught by the end-to-end demo.)
        typical_5m = max(p.n / max(p.active_hours, 1) / 12, 0.05)

        hour_rarity = 1.0 if p.n == 0 else 1 - (p.hours[hour] / max(p.hours.values()))
        is_new = p.n >= 5  # "new X" only means something once there is history

        b = float(evt.bytes_out or 0)
        if p.bytes_n > 5 and b > 0:
            std = math.sqrt(p.bytes_m2 / (p.bytes_n - 1)) or 1.0
            bytes_z = max(min((math.log1p(b) - p.bytes_mean) / max(std, 0.25), 10), -10)
        else:
            bytes_z = 0.0

        vec = [
            math.sin(2 * math.pi * hour / 24),
            math.cos(2 * math.pi * hour / 24),
            float(evt.timestamp.weekday() >= 5),
            hour_rarity,
            float(is_new and evt.geo_country is not None and evt.geo_country not in p.countries),
            float(is_new and evt.src_ip is not None and evt.src_ip not in p.ips),
            float(is_new and action not in p.actions),
            float(is_new and evt.target_resource is not None and evt.target_resource not in p.resources),
            self._rarity(p.actions[action], p.n, len(p.actions)),
            self._rarity(self.global_actions[action], self.global_n, len(self.global_actions)),
            self._rarity(p.transitions[(p.last_action, action)], max(p.n - 1, 0), len(p.transitions)),
            math.log1p(len(last_5m)),
            min(len(last_5m) / typical_5m, 50.0) / 10.0,
            float(sum(1 for r in last_10m if r[3])),
            float(len({r[1] for r in recent if r[1]})),
            float(len({r[2] for r in last_10m if r[2]})),
            float(len({r[4] for r in last_2m if r[4] is not None})),
            float(evt.outcome == "failure"),
            float(evt.privileged),
            float(action in SENSITIVE_ACTIONS),
            float(evt.category == "authentication" and evt.mfa is False and evt.principal_type != "service_account"),
            float(bool(evt.attributes.get("src_hosting"))),
            float(evt.src_ip is not None and not evt.attributes.get("src_internal", False)
                  and evt.principal_type == "service_account"),
            math.log1p(b) / 20.0,
            bytes_z / 5.0,
            *[float(evt.category == c) for c in CATEGORIES],
        ]
        if update:
            self.update(evt)
        return np.asarray(vec, dtype=np.float32)

    def update(self, evt: Event) -> None:
        p = self.profiles[evt.entity_key]
        ts = evt.timestamp.timestamp()
        hour_bucket = int(ts // 3600)
        if hour_bucket != p.last_hour:
            p.active_hours += 1
            p.last_hour = hour_bucket
        p.n += 1
        p.hours[evt.timestamp.hour] += 1
        if evt.geo_country:
            p.countries.add(evt.geo_country)
        if evt.src_ip:
            p.ips.add(evt.src_ip)
        p.actions[evt.action] += 1
        if evt.target_resource:
            p.resources.add(evt.target_resource)
        p.transitions[(p.last_action, evt.action)] += 1
        p.last_action = evt.action
        p.recent.append((ts, evt.src_ip, evt.target_resource, evt.outcome == "failure", evt.dst_port))
        if evt.bytes_out:
            x = math.log1p(evt.bytes_out)
            p.bytes_n += 1
            delta = x - p.bytes_mean
            p.bytes_mean += delta / p.bytes_n
            p.bytes_m2 += delta * (x - p.bytes_mean)
        self.global_actions[evt.action] += 1
        self.global_n += 1


def explain(vec: np.ndarray, baseline_mean: np.ndarray, baseline_std: np.ndarray, top: int = 4) -> list[dict]:
    """Which features made this event unusual? (z-score vs the training baseline).

    Not as rigorous as SHAP values, but cheap, model-agnostic and good enough to
    tell an analyst *why* the model fired ("new_country=1, hour_rarity=0.98").
    """
    z = np.clip((vec - baseline_mean) / np.maximum(baseline_std, 1e-3), -99, 99)
    order = np.argsort(-np.abs(z))[:top]
    return [{"feature": FEATURE_NAMES[i], "value": round(float(vec[i]), 3), "z": round(float(z[i]), 1)}
            for i in order if abs(z[i]) > 1.5]
