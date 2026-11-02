"""Generates benign ("normal") telemetry for the simulated company.

Activity is modelled as a non-homogeneous Poisson process: each identity has
an expected number of sessions per hour that depends on its working hours, so
humans are busy 9-18 local time and quiet at night while service accounts run
around the clock. A small amount of *benign weirdness* is injected on purpose
(typos, travel, on-call work at 3am, a legitimate IAM change) because real
networks are noisy and a detector that only works on perfectly clean data is
useless - these are the false positives we want to measure.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterator
from datetime import datetime, timedelta

from aegis.enrichment import geoip
from aegis.simulator import raw
from aegis.simulator.world import APP_PATHS, HOST_FLOWS, IDENTITIES, PERSONA_API, Identity

BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15"
SDK_UA = "Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/linux lang/python#3.12"


def _hourly_rate(identity: Identity, ts: datetime) -> float:
    """Expected sessions in the hour starting at `ts` (UTC)."""
    if identity.kind == "service":
        if identity.persona == "backup":
            return 1.0 if ts.hour in (2, 14) else 0.0
        return identity.sessions_per_day / 24
    local_hour = (ts.hour + identity.utc_offset) % 24
    weekend = ts.weekday() >= 5
    in_hours = identity.work_start <= local_hour < identity.work_end
    rate = identity.sessions_per_day / (identity.work_end - identity.work_start) if in_hours else 0.004
    if identity.persona == "sre" and not in_hours:
        rate = 0.02  # on-call engineers occasionally work at night (benign anomaly!)
    return rate * (identity.weekend_factor if weekend else 1.0)


def _poisson(rng: random.Random, lam: float) -> int:
    # Knuth's algorithm - fine for the small lambdas used here.
    if lam <= 0:
        return 0
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


class BaselineSimulator:
    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)

    # ------------------------------------------------------------------ sessions
    def human_session(self, who: Identity, ts: datetime) -> list[dict]:
        rng = self.rng
        out: list[dict] = []
        ip = rng.choice(who.ips)
        # benign anomaly: travelling user (~1.5% of sessions) logs in from Paris
        if rng.random() < 0.015:
            ip = f"198.51.100.{rng.randint(129, 140)}"
        geo = geoip(ip)
        t = ts
        # benign anomaly: password typos
        for _ in range(rng.choices([0, 1, 2, 3], weights=[90, 7, 2, 1])[0]):
            out.append(raw.idp_auth(rng, t, user=who.name, src_ip=ip, country=geo.country, city=geo.city,
                                    success=False, reason="INVALID_CREDENTIALS", user_agent=BROWSER_UA))
            t += timedelta(seconds=rng.randint(5, 40))
        privileged = who.aws_role in ("SREAdmin",)
        out.append(raw.idp_auth(rng, t, user=who.name, src_ip=ip, country=geo.country, city=geo.city,
                                success=True, mfa=True, privileged=privileged, user_agent=BROWSER_UA))
        t += timedelta(seconds=rng.randint(2, 10))
        out.append(raw.cloudtrail(
            rng, t, user=f"{who.aws_role}/{who.name}", identity_type="AssumedRole",
            event_source="sts.amazonaws.com", event_name="AssumeRoleWithSAML", src_ip=ip, user_agent=BROWSER_UA,
            request={"roleArn": f"arn:aws:iam::{raw.ACCOUNT_ID}:role/{who.aws_role}"}, mfa=True))

        api = PERSONA_API[who.persona]
        for _ in range(rng.randint(4, 14)):
            t += timedelta(seconds=rng.randint(10, 300))
            src, name, resource = rng.choice(api)
            out.append(raw.cloudtrail(
                rng, t, user=f"{who.aws_role}/{who.name}", identity_type="AssumedRole", event_source=src,
                event_name=name, src_ip=ip, user_agent=rng.choice([BROWSER_UA, SDK_UA]),
                request={"resource": resource}, mfa=True))

        # benign anomaly: an SRE legitimately creates a role / attaches a scoped policy
        if who.persona == "sre" and rng.random() < 0.04:
            t += timedelta(seconds=rng.randint(30, 200))
            out.append(raw.cloudtrail(
                rng, t, user=f"{who.aws_role}/{who.name}", identity_type="AssumedRole",
                event_source="iam.amazonaws.com", event_name="AttachRolePolicy", src_ip=ip,
                request={"roleName": "svc-etl", "policyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
                mfa=True, read_only=False))

        for ns in who.k8s_namespaces:
            for _ in range(rng.randint(0, 4)):
                t += timedelta(seconds=rng.randint(5, 120))
                verb, resource, sub = rng.choice([("get", "pods", None), ("list", "pods", None),
                                                  ("get", "deployments", None), ("get", "pods", "log")])
                out.append(raw.k8s_audit(rng, t, username=f"{who.name}@example.com", verb=verb, resource=resource,
                                         namespace=ns, subresource=sub, src_ip=ip))
            # benign: SREs sometimes exec into a prod pod while debugging
            if who.persona == "sre" and ns == "prod" and rng.random() < 0.05:
                t += timedelta(seconds=rng.randint(5, 60))
                out.append(raw.k8s_audit(rng, t, username=f"{who.name}@example.com", verb="create", resource="pods",
                                         namespace=ns, name="production-api-7d9f", subresource="exec", src_ip=ip))

        if who.persona in ("dev", "sre", "analyst"):
            for _ in range(rng.randint(0, 6)):
                t += timedelta(seconds=rng.randint(1, 90))
                method, path = rng.choice(APP_PATHS["human"])
                status = rng.choices([200, 201, 404, 401], weights=[85, 8, 5, 2])[0]
                out.append(raw.app_log(rng, t, method=method, path=path.format(id=rng.randint(1000, 9999)),
                                       status=status, client_ip=ip, user=who.name))
        return out

    def service_session(self, who: Identity, ts: datetime) -> list[dict]:
        rng = self.rng
        ip = who.internal_ip or who.ips[0]
        t = ts
        out = [raw.idp_auth(rng, t, user=who.name, src_ip=ip, country=None, city=None, success=True,
                            event_type="app.oauth2.as.token.grant", mfa=False, user_agent=SDK_UA)]
        api = PERSONA_API[who.persona]
        for _ in range(rng.randint(1, 4)):
            t += timedelta(seconds=rng.randint(1, 30))
            src, name, resource = rng.choice(api)
            out.append(raw.cloudtrail(rng, t, user=who.name, event_source=src, event_name=name, src_ip=ip,
                                      user_agent=SDK_UA, request={"resource": resource}))
        if who.persona == "ci" and rng.random() < 0.3:
            t += timedelta(seconds=rng.randint(5, 60))
            out.append(raw.k8s_audit(rng, t, username=f"system:serviceaccount:prod:{who.name}", verb="patch",
                                     resource="deployments", namespace="prod", name="production-api", src_ip=ip))
        if who.persona == "reporting":
            for _ in range(rng.randint(1, 3)):
                t += timedelta(seconds=rng.randint(1, 20))
                method, path = rng.choice(APP_PATHS["reporting"])
                out.append(raw.app_log(rng, t, method=method, path=path, status=200, client_ip=ip, user=who.name))
        return out

    def network_flows(self, ts: datetime) -> list[dict]:
        rng = self.rng
        out = []
        for src, flows in HOST_FLOWS.items():
            for dst, port, proto, typical in flows:
                if rng.random() < 0.3:
                    b = max(64, int(rng.lognormvariate(math.log(typical), 0.5)))
                    out.append(raw.vpc_flow(rng, ts + timedelta(seconds=rng.randint(0, 599)), src_ip=src,
                                            dst_ip=dst, dst_port=port, protocol=proto, bytes_=b))
        return out

    # ------------------------------------------------------------------ drivers
    def generate(self, start: datetime, hours: float) -> Iterator[dict]:
        """Yield benign envelopes between start and start+hours, sorted by time."""
        buffer: list[tuple[datetime, int, dict]] = []
        seq = 0
        steps = int(hours * 6)  # 10-minute steps
        for step in range(steps):
            slot = start + timedelta(minutes=10 * step)
            for who in IDENTITIES:
                for _ in range(_poisson(self.rng, _hourly_rate(who, slot) / 6)):
                    begin = slot + timedelta(seconds=self.rng.randint(0, 599))
                    session = self.human_session(who, begin) if who.kind == "human" else self.service_session(who, begin)
                    for env in session:
                        seq += 1
                        buffer.append((event_time(env), seq, env))
            for env in self.network_flows(slot):
                seq += 1
                buffer.append((event_time(env), seq, env))
        buffer.sort(key=lambda x: (x[0], x[1]))
        for _, _, env in buffer:
            yield env

    def random_activity(self, ts: datetime) -> list[dict]:
        """One burst of benign activity at `ts` - used by the live generator."""
        weights = [max(_hourly_rate(i, ts), 0.01) for i in IDENTITIES]
        who = self.rng.choices(IDENTITIES, weights=weights)[0]
        if self.rng.random() < 0.25:
            return self.network_flows(ts)[:3]
        return self.human_session(who, ts) if who.kind == "human" else self.service_session(who, ts)


def event_time(env: dict) -> datetime:
    """Extract the timestamp from any raw envelope (used for sorting)."""
    from aegis.collectors import parse_timestamp_from_envelope

    return parse_timestamp_from_envelope(env)
