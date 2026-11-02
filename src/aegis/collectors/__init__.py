"""Event collectors: parse raw logs from five sources into the normalized `Event` schema.

Each source gets a small `normalize_<source>()` function. They all:
1. parse the source-specific format,
2. map fields onto the common schema (who / from where / did what / to what),
3. extract security-relevant flags (privileged? MFA? failed?),
4. enrich with GeoIP + hosting-provider information,
5. build a deterministic `event_id` so a re-delivered Kafka message can be
   de-duplicated downstream (idempotency is essential with at-least-once delivery).
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from aegis.enrichment import geoip, is_internal
from aegis.schema import Event, GroundTruth


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def parse_timestamp_from_envelope(env: dict) -> datetime:
    rec = env["record"]
    src = env["source"]
    if src == "cloudtrail":
        return _parse_iso(rec["eventTime"])
    if src == "auth":
        return _parse_iso(rec["published"])
    if src == "k8s_audit":
        return _parse_iso(rec["requestReceivedTimestamp"])
    if src == "network":
        return datetime.fromtimestamp(int(rec.split()[10]), UTC)
    if src == "app":
        return _parse_iso(rec["ts"])
    raise ValueError(f"unknown source {src}")


def _event_id(source: str, unique: str) -> str:
    return "evt-" + hashlib.sha1(f"{source}:{unique}".encode()).hexdigest()[:16]


def _truth(env: dict) -> GroundTruth | None:
    t = env.get("_truth")
    return GroundTruth(**t) if t else None


def _enrich(evt: Event) -> Event:
    geo = geoip(evt.src_ip)
    if evt.geo_country is None and geo.country:
        evt.geo_country, evt.geo_city = geo.country, geo.city
    evt.attributes.setdefault("asn_org", geo.asn_org)
    evt.attributes["src_hosting"] = geo.is_hosting
    evt.attributes["src_internal"] = geo.is_internal
    if evt.dst_ip:
        evt.attributes["dst_internal"] = is_internal(evt.dst_ip)
    return evt


# --------------------------------------------------------------------- CloudTrail
_AUTH_EVENTS = {"ConsoleLogin", "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "GetSessionToken",
                "GetFederationToken"}
_RESOURCE_KEYS = ["resource", "bucketName", "roleName", "userName", "secretId", "name", "functionName",
                  "detectorId", "dbInstanceIdentifier"]


def normalize_cloudtrail(env: dict) -> Event:
    rec: dict[str, Any] = env["record"]
    ident = rec.get("userIdentity", {})
    name = rec["eventName"]
    src = rec["eventSource"]
    req = rec.get("requestParameters") or {}
    resp = rec.get("responseElements") or {}

    # AssumedRole identities look like "<Role>/<session>" - the session name is the human.
    principal, role = ident.get("userName"), None
    if ident.get("type") == "AssumedRole" and principal and "/" in principal:
        role, principal = principal.split("/", 1)
    if name.startswith("AssumeRole") and req.get("roleArn"):
        role = req["roleArn"].rsplit("/", 1)[-1]

    if name in _AUTH_EVENTS:
        category = "authentication"
    elif src == "iam.amazonaws.com":
        category = "iam"
    elif rec.get("readOnly"):
        category = "api"
    else:
        category = "resource"

    target = next((str(req[k]) for k in _RESOURCE_KEYS if k in req), None)
    if isinstance(req.get("flowLogIds"), list):
        target = ",".join(req["flowLogIds"])
    if name == "RunInstances":
        target = req.get("resource", target)

    attrs: dict[str, Any] = {"event_source": src, "read_only": bool(rec.get("readOnly")), "role": role,
                             "request": req}
    if name == "RunInstances":
        items = (resp.get("instancesSet") or {}).get("items") or []
        if items:
            attrs["instance_id"] = items[0].get("instanceId")
            attrs["private_ip"] = items[0].get("privateIpAddress")
        attrs["instance_type"] = req.get("instanceType")
    if name == "CreateAccessKey" and resp.get("accessKey"):
        attrs["created_access_key"] = resp["accessKey"].get("accessKeyId")
    if "policyArn" in req:
        attrs["policy_arn"] = req["policyArn"]
    if rec.get("errorCode"):
        attrs["error_code"] = rec["errorCode"]

    mfa_raw = ((ident.get("sessionContext") or {}).get("attributes") or {}).get("mfaAuthenticated")
    mfa = None if mfa_raw is None else mfa_raw == "true"
    privileged = bool(role and "admin" in role.lower()) or (category == "iam" and not rec.get("readOnly"))
    bytes_out = (rec.get("additionalEventData") or {}).get("bytesTransferredOut")

    evt = Event(
        event_id=_event_id("cloudtrail", rec["eventID"]),
        timestamp=_parse_iso(rec["eventTime"]),
        source="cloudtrail",
        category=category,
        action=name,
        outcome="failure" if rec.get("errorCode") else "success",
        principal=principal,
        principal_type="service_account" if principal and principal.startswith("service-account") else "user",
        src_ip=rec.get("sourceIPAddress"),
        user_agent=rec.get("userAgent"),
        target_resource=target,
        resource_type=src.split(".")[0],
        bytes_out=bytes_out,
        privileged=privileged,
        mfa=mfa,
        attributes=attrs,
        truth=_truth(env),
    )
    return _enrich(evt)


# --------------------------------------------------------------------- IdP auth
def normalize_auth(env: dict) -> Event:
    rec = env["record"]
    client = rec.get("client", {})
    geo = client.get("geographicalContext") or {}
    actor = rec["actor"]["alternateId"]
    target = (rec.get("target") or [{}])[0]
    evt = Event(
        event_id=_event_id("auth", rec["uuid"]),
        timestamp=_parse_iso(rec["published"]),
        source="auth",
        category="authentication",
        action=rec["eventType"],
        outcome="success" if rec["outcome"]["result"] == "SUCCESS" else "failure",
        principal=actor,
        principal_type="service_account" if actor.startswith("service-account") else "user",
        src_ip=client.get("ipAddress"),
        geo_country=geo.get("country"),
        geo_city=geo.get("city"),
        user_agent=(client.get("userAgent") or {}).get("rawUserAgent"),
        target_resource=target.get("displayName"),
        resource_type="sso_app",
        privileged=bool(target.get("privileged")),
        mfa=(rec.get("authenticationContext") or {}).get("mfa"),
        attributes={"reason": rec["outcome"].get("reason")},
        truth=_truth(env),
    )
    return _enrich(evt)


# --------------------------------------------------------------------- Kubernetes audit
def _k8s_principal(username: str) -> tuple[str, str]:
    if username.startswith("system:serviceaccount:"):
        _, _, ns, name = username.split(":", 3)
        # Identity resolution: workloads that run as a known org service account
        # map onto the same principal used by the IdP and CloudTrail.
        return (name if name.startswith("service-account-") else f"k8s-sa:{ns}/{name}"), "service_account"
    return username.split("@")[0], "user"


def normalize_k8s(env: dict) -> Event:
    rec = env["record"]
    ref = rec.get("objectRef") or {}
    principal, ptype = _k8s_principal(rec["user"]["username"])
    resource = ref.get("resource")
    sub = ref.get("subresource")
    code = (rec.get("responseStatus") or {}).get("code", 200)
    body = rec.get("requestObject") or {}
    spec = body.get("spec") or {}
    privileged_pod = any((c.get("securityContext") or {}).get("privileged") for c in spec.get("containers", []))
    host_path = any("hostPath" in v for v in spec.get("volumes", []))
    host_ns = bool(spec.get("hostPID") or spec.get("hostNetwork"))
    role_ref = (body.get("roleRef") or {}).get("name")
    ns, name = ref.get("namespace"), ref.get("name")
    evt = Event(
        event_id=_event_id("k8s_audit", rec["auditID"]),
        timestamp=_parse_iso(rec["requestReceivedTimestamp"]),
        source="k8s_audit",
        category="kubernetes",
        action=f"{rec['verb']} {resource}" + (f"/{sub}" if sub else ""),
        outcome="success" if code < 400 else "failure",
        principal=principal,
        principal_type=ptype,
        src_ip=(rec.get("sourceIPs") or [None])[0],
        user_agent=rec.get("userAgent"),
        target_resource=f"{ns}/{name}" if ns and name else (name or ns or resource),
        resource_type=f"k8s:{resource}",
        privileged=privileged_pod or host_path or host_ns or role_ref == "cluster-admin",
        attributes={
            "verb": rec["verb"], "resource": resource, "subresource": sub, "namespace": ns, "name": name,
            "code": code, "privileged_pod": privileged_pod, "host_path": host_path, "host_namespaces": host_ns,
            "role_ref": role_ref, "cluster": (rec.get("annotations") or {}).get("cluster"),
        },
        truth=_truth(env),
    )
    return _enrich(evt)


# --------------------------------------------------------------------- VPC flow logs
_PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}


def normalize_network(env: dict) -> Event:
    line: str = env["record"]
    (_v, _acct, eni, src, dst, sport, dport, proto, packets, nbytes, start, _end, action, _status) = line.split()
    evt = Event(
        event_id=_event_id("network", hashlib.sha1(line.encode()).hexdigest()),
        timestamp=datetime.fromtimestamp(int(start), UTC),
        source="network",
        category="network",
        action="flow",
        outcome="success" if action == "ACCEPT" else "failure",
        principal=None,
        principal_type="host",
        src_ip=src,
        dst_ip=dst,
        dst_port=int(dport),
        protocol=_PROTO.get(proto, proto),
        bytes_out=int(nbytes),
        target_resource=dst,
        resource_type="ip",
        attributes={"eni": eni, "src_port": int(sport), "packets": int(packets), "flow_action": action},
        truth=_truth(env),
    )
    dst_geo = geoip(dst)
    evt.attributes["dst_country"] = dst_geo.country
    evt.attributes["dst_hosting"] = dst_geo.is_hosting
    return _enrich(evt)


# --------------------------------------------------------------------- application logs
_ID_RE = re.compile(r"/\d+")


def normalize_app(env: dict) -> Event:
    rec = env["record"]
    path = _ID_RE.sub("/{id}", rec["path"])
    evt = Event(
        event_id=_event_id("app", rec["request_id"]),
        timestamp=_parse_iso(rec["ts"]),
        source="app",
        category="application",
        action=f"{rec['method']} {path}",
        outcome="success" if rec["status"] < 400 else "failure",
        principal=rec.get("user"),
        principal_type="service_account" if (rec.get("user") or "").startswith("service-account") else "user",
        src_ip=rec.get("client_ip"),
        target_resource=rec["service"],
        resource_type="service",
        bytes_out=rec.get("bytes"),
        privileged=path.startswith("/admin"),
        attributes={"status": rec["status"], "path": path, "method": rec["method"], "latency_ms": rec["latency_ms"]},
        truth=_truth(env),
    )
    return _enrich(evt)


NORMALIZERS = {
    "cloudtrail": normalize_cloudtrail,
    "auth": normalize_auth,
    "k8s_audit": normalize_k8s,
    "network": normalize_network,
    "app": normalize_app,
}


def normalize(env: dict) -> Event:
    return NORMALIZERS[env["source"]](env)
