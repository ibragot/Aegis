"""Attack scenarios - safe, synthetic replays of common cloud intrusion patterns.

Nothing here touches a real system: each scenario returns raw log *records*
that look like what CloudTrail / the IdP / Kubernetes / VPC flow logs would
record if the attack had happened. Every record carries a ground-truth label
(`_truth`) so we can grade the detectors.

The flagship scenario (`credential_compromise`) reproduces the storyline from
the project brief:

    14:03 Login from unusual location
    14:04 Repeated authentication failures
    14:05 Successful privileged login
    14:07 Permission changes
    14:08 New cloud resource created
    14:10 Unusual API requests (+ data leaving the network)
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import datetime, timedelta

from aegis.enrichment import geoip
from aegis.simulator import raw

ATTACKER_UA = "python-requests/2.31.0"
ATTACKER_CLI = "aws-cli/2.13.0 Python/3.11.4 Linux/5.15 exe/x86_64.kali"


def _truth(scenario: str, stage: str) -> dict:
    return {"malicious": True, "scenario": scenario, "stage": stage}


def credential_compromise(rng: random.Random, start: datetime, target: str = "service-account-17") -> list[dict]:
    s = "credential_compromise"
    ip = f"203.0.113.{rng.randint(5, 60)}"
    geo = geoip(ip)
    t = start
    out: list[dict] = []

    # 14:03 - stolen client secret used from a VPS in an unusual country
    out.append(raw.idp_auth(rng, t, user=target, src_ip=ip, country=geo.country, city=geo.city, success=True,
                            event_type="app.oauth2.as.token.grant", mfa=False, user_agent=ATTACKER_UA,
                            truth=_truth(s, "initial_access")))
    # 14:04 - attacker tries to obtain an admin-scoped session and fails repeatedly
    t += timedelta(minutes=1)
    for _ in range(rng.randint(6, 9)):
        t += timedelta(seconds=rng.randint(3, 7))
        out.append(raw.idp_auth(rng, t, user=target, src_ip=ip, country=geo.country, city=geo.city, success=False,
                                event_type="user.session.start", mfa=False, privileged=True,
                                reason="INVALID_CREDENTIALS", user_agent=ATTACKER_UA,
                                truth=_truth(s, "credential_access")))
    # 14:05 - succeeds: privileged admin session without MFA
    t = start + timedelta(minutes=2)
    out.append(raw.idp_auth(rng, t, user=target, src_ip=ip, country=geo.country, city=geo.city, success=True,
                            mfa=False, privileged=True, user_agent=ATTACKER_UA, truth=_truth(s, "privileged_login")))
    t += timedelta(seconds=20)
    out.append(raw.cloudtrail(rng, t, user=target, event_source="sts.amazonaws.com", event_name="AssumeRole",
                              src_ip=ip, user_agent=ATTACKER_CLI, mfa=False,
                              request={"roleArn": f"arn:aws:iam::{raw.ACCOUNT_ID}:role/ProdAdmin",
                                       "roleSessionName": target},
                              truth=_truth(s, "privileged_login")))
    # 14:07 - permission changes (privilege escalation + persistence)
    t = start + timedelta(minutes=4)
    out.append(raw.cloudtrail(rng, t, user=target, event_source="iam.amazonaws.com", event_name="AttachRolePolicy",
                              src_ip=ip, user_agent=ATTACKER_CLI, read_only=False,
                              request={"roleName": f"{target}-role",
                                       "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                              truth=_truth(s, "privilege_escalation")))
    t += timedelta(seconds=25)
    out.append(raw.cloudtrail(rng, t, user=target, event_source="iam.amazonaws.com", event_name="CreateUser",
                              src_ip=ip, user_agent=ATTACKER_CLI, read_only=False,
                              request={"userName": "svc-backup-admin"}, truth=_truth(s, "persistence")))
    t += timedelta(seconds=10)
    out.append(raw.cloudtrail(rng, t, user=target, event_source="iam.amazonaws.com", event_name="CreateAccessKey",
                              src_ip=ip, user_agent=ATTACKER_CLI, read_only=False,
                              request={"userName": "svc-backup-admin"},
                              response={"accessKey": {"accessKeyId": "AKIAEXAMPLEPERSIST1", "status": "Active"}},
                              truth=_truth(s, "persistence")))
    # 14:08 - new cloud resource: GPU instance in the production subnet + privileged pod
    t = start + timedelta(minutes=5)
    instance_ip = f"10.0.9.{rng.randint(50, 99)}"
    out.append(raw.cloudtrail(rng, t, user=target, event_source="ec2.amazonaws.com", event_name="RunInstances",
                              src_ip=ip, user_agent=ATTACKER_CLI, read_only=False,
                              request={"instanceType": "p3.8xlarge", "subnetId": "subnet-prod-a",
                                       "resource": "production-api"},
                              response={"instancesSet": {"items": [{"instanceId": "i-0attacker9f3c",
                                                                    "privateIpAddress": instance_ip}]}},
                              truth=_truth(s, "execution")))
    t += timedelta(seconds=30)
    out.append(raw.k8s_audit(rng, t, username=f"system:serviceaccount:prod:{target}", verb="create",
                             resource="pods", namespace="prod", name="debug-tools", code=201, src_ip=ip,
                             request_object={"spec": {"hostPID": True, "containers": [
                                 {"name": "tools", "image": "alpine:3.19",
                                  "securityContext": {"privileged": True}}],
                                 "volumes": [{"name": "host", "hostPath": {"path": "/"}}]}},
                             truth=_truth(s, "execution")))
    # 14:10 - unusual API requests: secret harvesting, bulk export from the API, data leaves the network
    t = start + timedelta(minutes=7)
    out.append(raw.cloudtrail(rng, t, user=target, event_source="secretsmanager.amazonaws.com",
                              event_name="ListSecrets", src_ip=ip, user_agent=ATTACKER_CLI,
                              truth=_truth(s, "discovery")))
    for name in ["prod/payments-db", "prod/stripe-key", "prod/jwt-signing", "prod/datadog", "prod/github-token",
                 "prod/smtp"]:
        t += timedelta(seconds=rng.randint(2, 6))
        out.append(raw.cloudtrail(rng, t, user=target, event_source="secretsmanager.amazonaws.com",
                                  event_name="GetSecretValue", src_ip=ip, user_agent=ATTACKER_CLI,
                                  request={"secretId": name}, truth=_truth(s, "credential_access")))
    for _ in range(rng.randint(30, 45)):
        t += timedelta(seconds=rng.uniform(0.5, 2.5))
        out.append(raw.app_log(rng, t, method="GET", path="/admin/export/customers", status=200, client_ip=ip,
                               user=target, bytes_=rng.randint(400_000, 900_000),
                               truth=_truth(s, "collection")))
    t += timedelta(seconds=20)
    for _ in range(3):
        t += timedelta(seconds=rng.randint(10, 40))
        out.append(raw.vpc_flow(rng, t, src_ip=instance_ip, dst_ip=f"203.0.113.{rng.randint(200, 250)}",
                                dst_port=443, bytes_=rng.randint(80_000_000, 400_000_000),
                                truth=_truth(s, "exfiltration")))
    return out


def password_spray(rng: random.Random, start: datetime) -> list[dict]:
    s = "password_spray"
    ip = f"203.0.113.{rng.randint(70, 120)}"
    geo = geoip(ip)
    users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory",
             "oscar", "peggy", "trent", "victor"]
    t = start
    out = []
    for u in users:
        for _ in range(rng.randint(1, 2)):
            t += timedelta(seconds=rng.randint(2, 12))
            out.append(raw.idp_auth(rng, t, user=u, src_ip=ip, country=geo.country, city=geo.city, success=False,
                                    reason="INVALID_CREDENTIALS", mfa=False, user_agent=ATTACKER_UA,
                                    truth=_truth(s, "credential_access")))
    victim = "frank"
    t += timedelta(seconds=30)
    out.append(raw.idp_auth(rng, t, user=victim, src_ip=ip, country=geo.country, city=geo.city, success=True,
                            mfa=False, user_agent=ATTACKER_UA, truth=_truth(s, "initial_access")))
    t += timedelta(seconds=15)
    out.append(raw.cloudtrail(rng, t, user=f"Developer/{victim}", identity_type="AssumedRole",
                              event_source="sts.amazonaws.com", event_name="AssumeRoleWithSAML", src_ip=ip,
                              user_agent=ATTACKER_UA, mfa=False,
                              request={"roleArn": f"arn:aws:iam::{raw.ACCOUNT_ID}:role/Developer"},
                              truth=_truth(s, "initial_access")))
    for name in ["ListBuckets", "DescribeInstances", "ListUsers", "ListRoles", "GetAccountAuthorizationDetails"]:
        t += timedelta(seconds=rng.randint(3, 15))
        src = {"ListBuckets": "s3", "DescribeInstances": "ec2"}.get(name, "iam") + ".amazonaws.com"
        out.append(raw.cloudtrail(rng, t, user=f"Developer/{victim}", identity_type="AssumedRole",
                                  event_source=src, event_name=name, src_ip=ip, user_agent=ATTACKER_CLI,
                                  error_code="AccessDenied" if src.startswith("iam") else None,
                                  truth=_truth(s, "discovery")))
    return out


def k8s_compromise(rng: random.Random, start: datetime) -> list[dict]:
    s = "k8s_compromise"
    sa = "system:serviceaccount:staging:web"
    pod_ip = f"10.0.7.{rng.randint(10, 40)}"
    t = start
    out = []
    for name in ["kube-system/aws-creds", "kube-system/admin-token", "prod/db-password", "prod/api-keys"]:
        t += timedelta(seconds=rng.randint(2, 8))
        ns, secret = name.split("/")
        out.append(raw.k8s_audit(rng, t, username=sa, verb="get", resource="secrets", namespace=ns, name=secret,
                                 code=403, src_ip=pod_ip, truth=_truth(s, "discovery")))
    t += timedelta(seconds=40)
    out.append(raw.k8s_audit(rng, t, username=sa, verb="create", resource="pods", namespace="staging",
                             name="node-shell", code=201, src_ip=pod_ip,
                             request_object={"spec": {"hostNetwork": True, "containers": [
                                 {"name": "shell", "image": "busybox", "securityContext": {"privileged": True}}],
                                 "volumes": [{"name": "root", "hostPath": {"path": "/"}}]}},
                             truth=_truth(s, "privilege_escalation")))
    t += timedelta(seconds=20)
    out.append(raw.k8s_audit(rng, t, username=sa, verb="create", resource="pods", namespace="staging",
                             name="node-shell", subresource="exec", code=101, src_ip=pod_ip,
                             truth=_truth(s, "execution")))
    t += timedelta(seconds=60)
    out.append(raw.k8s_audit(rng, t, username=sa, verb="create", resource="clusterrolebindings", namespace=None,
                             name="staging-web-admin", code=201, src_ip=pod_ip,
                             request_object={"roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                                             "subjects": [{"kind": "ServiceAccount", "name": "web",
                                                           "namespace": "staging"}]},
                             truth=_truth(s, "persistence")))
    t += timedelta(seconds=30)
    out.append(raw.k8s_audit(rng, t, username=sa, verb="list", resource="secrets", namespace="prod", code=200,
                             src_ip=pod_ip, truth=_truth(s, "credential_access")))
    return out


def defense_evasion(rng: random.Random, start: datetime) -> list[dict]:
    s = "defense_evasion"
    ip = f"203.0.113.{rng.randint(130, 180)}"
    geo = geoip(ip)
    user = "SREAdmin/carol"
    t = start
    out = [raw.idp_auth(rng, t, user="carol", src_ip=ip, country=geo.country, city=geo.city, success=True,
                        mfa=True, privileged=True, user_agent=ATTACKER_UA, truth=_truth(s, "initial_access"))]
    for name, src, req in [
        ("StopLogging", "cloudtrail.amazonaws.com", {"name": "cloudtrail-main"}),
        ("DeleteTrail", "cloudtrail.amazonaws.com", {"name": "cloudtrail-main"}),
        ("DeleteFlowLogs", "ec2.amazonaws.com", {"flowLogIds": ["fl-prod-vpc"]}),
        ("DeleteDetector", "guardduty.amazonaws.com", {"detectorId": "gd-main"}),
    ]:
        t += timedelta(seconds=rng.randint(10, 40))
        out.append(raw.cloudtrail(rng, t, user=user, identity_type="AssumedRole", event_source=src, event_name=name,
                                  src_ip=ip, user_agent=ATTACKER_CLI, request=req, read_only=False, mfa=True,
                                  truth=_truth(s, "defense_evasion")))
    return out


def data_exfiltration(rng: random.Random, start: datetime) -> list[dict]:
    """Insider: analyst bulk-downloads the customer-data bucket at night."""
    s = "data_exfiltration"
    ip = "198.51.100.50"
    user = "DataAnalyst/dave"
    t = start
    out = []
    for i in range(rng.randint(60, 90)):
        t += timedelta(seconds=rng.uniform(1, 5))
        out.append(raw.cloudtrail(rng, t, user=user, identity_type="AssumedRole", event_source="s3.amazonaws.com",
                                  event_name="GetObject", src_ip=ip, user_agent="rclone/v1.66.0", mfa=True,
                                  request={"bucketName": "aegis-customer-data", "key": f"exports/customers-{i:04d}.csv"},
                                  additional={"bytesTransferredOut": rng.randint(5_000_000, 25_000_000)},
                                  truth=_truth(s, "collection")))
    return out


def internal_recon(rng: random.Random, start: datetime) -> list[dict]:
    s = "internal_recon"
    host = f"10.0.3.{rng.randint(20, 25)}"
    t = start
    out = []
    for port in rng.sample(range(1, 10000), 40):
        t += timedelta(seconds=rng.uniform(0.2, 2))
        out.append(raw.vpc_flow(rng, t, src_ip=host, dst_ip=f"10.0.1.{rng.randint(10, 14)}", dst_port=port,
                                bytes_=60, packets=1, action="REJECT", truth=_truth(s, "discovery")))
    for _ in range(20):
        t += timedelta(seconds=rng.uniform(0.5, 3))
        out.append(raw.vpc_flow(rng, t, src_ip=host, dst_ip=raw_choice(rng), dst_port=22, bytes_=rng.randint(200, 900),
                                truth=_truth(s, "lateral_movement")))
    return out


def raw_choice(rng: random.Random) -> str:
    return f"10.0.1.{rng.randint(10, 14)}"


SCENARIOS: dict[str, Callable[[random.Random, datetime], list[dict]]] = {
    "credential_compromise": credential_compromise,
    "password_spray": password_spray,
    "k8s_compromise": k8s_compromise,
    "defense_evasion": defense_evasion,
    "data_exfiltration": data_exfiltration,
    "internal_recon": internal_recon,
}

DESCRIPTIONS = {
    "credential_compromise": "Stolen service-account credential -> privileged login -> IAM changes -> GPU instance "
                             "+ privileged pod -> secret harvesting -> bulk export -> exfiltration",
    "password_spray": "One external IP tries a few passwords against many users, one succeeds, then enumerates IAM",
    "k8s_compromise": "Compromised web pod probes secrets, launches a privileged hostPath pod, execs into it and "
                      "binds itself to cluster-admin",
    "defense_evasion": "Hijacked SRE session disables CloudTrail, VPC flow logs and GuardDuty",
    "data_exfiltration": "Insider bulk-downloads the customer-data S3 bucket with rclone at night",
    "internal_recon": "Compromised batch worker port-scans production nodes and attempts SSH lateral movement",
}


def run_scenario(name: str, start: datetime, seed: int | None = None) -> list[dict]:
    rng = random.Random(seed)
    return SCENARIOS[name](rng, start)
