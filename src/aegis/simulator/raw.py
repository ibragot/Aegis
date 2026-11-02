"""Builders that produce *raw* log records in (simplified) real-world formats.

The point of emitting realistic raw formats - instead of generating Aegis
`Event` objects directly - is that the collectors then have to do the same
parsing / normalization work a real SIEM does. Formats imitated:

* AWS CloudTrail          -> JSON records (`eventName`, `userIdentity`, ...)
* Identity provider (IdP) -> Okta System Log style JSON
* Kubernetes audit log    -> `audit.k8s.io/v1` Event objects
* VPC Flow Logs           -> the space separated version-2 text format
* Application logs        -> JSON lines from the production-api web service

Every builder returns an *envelope*: {"source", "record", "_truth"}.
`_truth` is simulator metadata (ground-truth labels) used only for evaluation.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rid(rng: random.Random, n: int = 32) -> str:
    return f"{rng.getrandbits(n * 4):0{n}x}"


def envelope(source: str, record: Any, truth: dict | None = None) -> dict:
    env = {"source": source, "record": record}
    if truth:
        env["_truth"] = truth
    return env


def cloudtrail(
    rng: random.Random,
    ts: datetime,
    *,
    user: str,
    identity_type: str = "IAMUser",
    event_source: str,
    event_name: str,
    src_ip: str,
    user_agent: str = "aws-cli/2.15.0 Python/3.11",
    request: dict | None = None,
    response: dict | None = None,
    error_code: str | None = None,
    mfa: bool | None = None,
    additional: dict | None = None,
    read_only: bool | None = None,
    truth: dict | None = None,
) -> dict:
    if identity_type == "AssumedRole":
        arn = f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{user}"
    else:
        arn = f"arn:aws:iam::{ACCOUNT_ID}:user/{user}"
    record: dict[str, Any] = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": identity_type,
            "principalId": _rid(rng, 20).upper(),
            "arn": arn,
            "accountId": ACCOUNT_ID,
            "userName": user,
            "accessKeyId": "AKIA" + _rid(rng, 16).upper(),
            "sessionContext": {"attributes": {"mfaAuthenticated": str(bool(mfa)).lower()}} if mfa is not None else {},
        },
        "eventTime": _iso(ts),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": REGION,
        "sourceIPAddress": src_ip,
        "userAgent": user_agent,
        "requestParameters": request or {},
        "responseElements": response,
        "eventID": f"{_rid(rng, 8)}-{_rid(rng, 4)}-{_rid(rng, 4)}-{_rid(rng, 4)}-{_rid(rng, 12)}",
        "eventType": "AwsConsoleSignIn" if event_name == "ConsoleLogin" else "AwsApiCall",
        "readOnly": read_only if read_only is not None else event_name.startswith(("Get", "List", "Describe")),
        "recipientAccountId": ACCOUNT_ID,
    }
    if error_code:
        record["errorCode"] = error_code
        record["errorMessage"] = f"User: {arn} is not authorized to perform this operation"
    if additional:
        record["additionalEventData"] = additional
    return envelope("cloudtrail", record, truth)


def idp_auth(
    rng: random.Random,
    ts: datetime,
    *,
    user: str,
    src_ip: str,
    country: str | None,
    city: str | None,
    success: bool,
    event_type: str = "user.session.start",
    mfa: bool = True,
    privileged: bool = False,
    reason: str | None = None,
    user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    truth: dict | None = None,
) -> dict:
    record = {
        "uuid": f"{_rid(rng, 8)}-{_rid(rng, 4)}-{_rid(rng, 4)}-{_rid(rng, 12)}",
        "published": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "eventType": event_type,
        "actor": {"alternateId": user, "type": "User" if not user.startswith("service-account") else "PublicClientApp"},
        "client": {
            "ipAddress": src_ip,
            "userAgent": {"rawUserAgent": user_agent},
            "geographicalContext": {"country": country, "city": city},
        },
        "outcome": {"result": "SUCCESS" if success else "FAILURE", "reason": reason},
        "authenticationContext": {"authenticationStep": 0, "mfa": mfa},
        "target": [{"type": "AppInstance", "displayName": "AWS IAM Identity Center", "privileged": privileged}],
    }
    return envelope("auth", record, truth)


def k8s_audit(
    rng: random.Random,
    ts: datetime,
    *,
    username: str,
    verb: str,
    resource: str,
    namespace: str | None,
    name: str | None = None,
    subresource: str | None = None,
    code: int = 200,
    src_ip: str = "10.0.1.50",
    request_object: dict | None = None,
    groups: list[str] | None = None,
    truth: dict | None = None,
) -> dict:
    record = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse" if request_object else "Metadata",
        "auditID": f"{_rid(rng, 8)}-{_rid(rng, 4)}-{_rid(rng, 4)}-{_rid(rng, 12)}",
        "stage": "ResponseComplete",
        "requestURI": f"/api/v1/namespaces/{namespace}/{resource}" + (f"/{name}" if name else ""),
        "verb": verb,
        "user": {"username": username, "groups": groups or ["system:authenticated"]},
        "sourceIPs": [src_ip],
        "userAgent": "kubectl/v1.30.2 (linux/amd64)",
        "objectRef": {
            "resource": resource,
            "namespace": namespace,
            "name": name,
            "subresource": subresource,
            "apiVersion": "v1",
        },
        "responseStatus": {"code": code},
        "requestObject": request_object,
        "requestReceivedTimestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        "annotations": {"cluster": "prod-cluster"},
    }
    return envelope("k8s_audit", record, truth)


def vpc_flow(
    rng: random.Random,
    ts: datetime,
    *,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: int = 6,
    bytes_: int | None = None,
    packets: int | None = None,
    action: str = "ACCEPT",
    src_port: int | None = None,
    truth: dict | None = None,
) -> dict:
    bytes_ = bytes_ if bytes_ is not None else rng.randint(400, 60_000)
    packets = packets if packets is not None else max(1, bytes_ // 900)
    start = int(ts.timestamp())
    line = (
        f"2 {ACCOUNT_ID} eni-{_rid(rng, 8)} {src_ip} {dst_ip} {src_port or rng.randint(32768, 60999)} "
        f"{dst_port} {protocol} {packets} {bytes_} {start} {start + 60} {action} OK"
    )
    return envelope("network", line, truth)


def app_log(
    rng: random.Random,
    ts: datetime,
    *,
    method: str,
    path: str,
    status: int,
    client_ip: str,
    user: str | None,
    service: str = "production-api",
    bytes_: int | None = None,
    truth: dict | None = None,
) -> dict:
    record = {
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "service": service,
        "level": "INFO" if status < 400 else "WARN",
        "method": method,
        "path": path,
        "status": status,
        "client_ip": client_ip,
        "user": user,
        "bytes": bytes_ if bytes_ is not None else rng.randint(200, 20_000),
        "latency_ms": round(rng.uniform(4, 180), 1),
        "request_id": _rid(rng, 16),
    }
    return envelope("app", record, truth)
