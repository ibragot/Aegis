"""The simulated company: identities, hosts and their *normal* behaviour.

Anomaly detection only works if "normal" has structure, so every identity here
has a home location, working hours and a characteristic set of API calls. The
ML models learn these patterns; the attack scenarios then break them.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Identity:
    name: str
    kind: str  # human | service
    persona: str  # dev | sre | analyst | security | finance | ci | backup | metrics | reporting | etl
    ips: list[str]
    utc_offset: float = 0.0  # hours, used for working hours
    work_start: int = 9
    work_end: int = 18
    sessions_per_day: float = 2.0
    weekend_factor: float = 0.1
    aws_role: str = "Developer"
    k8s_namespaces: list[str] = field(default_factory=lambda: ["staging"])
    internal_ip: str | None = None  # workstation / workload IP inside the VPC


HUMANS = [
    Identity("alice", "human", "dev", ["198.51.100.3", "198.51.100.150"], -8, k8s_namespaces=["staging"]),
    Identity("bob", "human", "dev", ["198.51.100.19"], -6, k8s_namespaces=["staging"]),
    Identity(
        "carol", "human", "sre", ["198.51.100.35", "198.51.100.150"], -5, aws_role="SREAdmin",
        k8s_namespaces=["prod", "staging"], sessions_per_day=2.5, weekend_factor=0.3,
    ),
    Identity("dave", "human", "analyst", ["198.51.100.50"], 0, aws_role="DataAnalyst", k8s_namespaces=[]),
    Identity("erin", "human", "security", ["198.51.100.66"], 1, aws_role="SecurityAudit", k8s_namespaces=["prod"]),
    Identity("frank", "human", "dev", ["198.51.100.83"], 5.5, k8s_namespaces=["staging"]),
    Identity("grace", "human", "finance", ["198.51.100.99"], -6, aws_role="BillingReadOnly", k8s_namespaces=[],
             sessions_per_day=1.2),
    Identity(
        "heidi", "human", "sre", ["198.51.100.115", "198.51.100.150"], -5, aws_role="SREAdmin",
        k8s_namespaces=["prod", "staging"], weekend_factor=0.3,
    ),
]

_SERVICE_PERSONAS = ["ci", "backup", "metrics", "reporting", "etl"]


def _service_accounts() -> list[Identity]:
    out = []
    for i in range(1, 21):
        persona = _SERVICE_PERSONAS[(i - 1) % len(_SERVICE_PERSONAS)]
        ip = f"10.0.2.{i}"
        out.append(
            Identity(
                name=f"service-account-{i}",
                kind="service",
                persona=persona,
                ips=[ip],
                internal_ip=ip,
                work_start=0,
                work_end=24,
                sessions_per_day=24 if persona != "backup" else 2,
                weekend_factor=1.0,
                aws_role=f"svc-{persona}",
                k8s_namespaces=["prod"] if persona == "ci" else [],
            )
        )
    return out


SERVICE_ACCOUNTS = _service_accounts()
IDENTITIES = HUMANS + SERVICE_ACCOUNTS
BY_NAME = {i.name: i for i in IDENTITIES}

# Internal hosts that generate network flows (src -> list of (dst, port, proto, typical bytes)).
DNS = "10.0.0.2"
PAYMENTS_DB = "10.0.4.5"
SAAS_MONITORING = "192.0.2.50"
SAAS_GIT = "192.0.2.10"
S3_ENDPOINT = "192.0.2.80"

HOST_FLOWS: dict[str, list[tuple[str, int, int, int]]] = {}
for _i in range(10, 15):  # production-api nodes
    HOST_FLOWS[f"10.0.1.{_i}"] = [
        (PAYMENTS_DB, 5432, 6, 40_000),
        (SAAS_MONITORING, 443, 6, 15_000),
        (DNS, 53, 17, 300),
        (S3_ENDPOINT, 443, 6, 120_000),
    ]
for _i in range(20, 26):  # batch workers
    HOST_FLOWS[f"10.0.3.{_i}"] = [(S3_ENDPOINT, 443, 6, 900_000), (DNS, 53, 17, 300), (PAYMENTS_DB, 5432, 6, 20_000)]
HOST_FLOWS["10.0.5.10"] = [(SAAS_GIT, 443, 6, 2_000_000), (DNS, 53, 17, 300), (S3_ENDPOINT, 443, 6, 500_000)]

# Typical AWS API calls per persona: (eventSource, eventName, resource template)
PERSONA_API: dict[str, list[tuple[str, str, str]]] = {
    "dev": [
        ("ec2.amazonaws.com", "DescribeInstances", "staging-web"),
        ("s3.amazonaws.com", "GetObject", "aegis-dev-artifacts"),
        ("s3.amazonaws.com", "PutObject", "aegis-dev-artifacts"),
        ("logs.amazonaws.com", "GetLogEvents", "staging-web"),
        ("lambda.amazonaws.com", "ListFunctions", "staging"),
        ("ecr.amazonaws.com", "DescribeImages", "staging-web"),
    ],
    "sre": [
        ("ec2.amazonaws.com", "DescribeInstances", "production-api"),
        ("eks.amazonaws.com", "DescribeCluster", "prod-cluster"),
        ("cloudwatch.amazonaws.com", "GetMetricData", "production-api"),
        ("logs.amazonaws.com", "GetLogEvents", "production-api"),
        ("autoscaling.amazonaws.com", "UpdateAutoScalingGroup", "production-api"),
        ("rds.amazonaws.com", "DescribeDBInstances", "payments-db"),
    ],
    "analyst": [
        ("athena.amazonaws.com", "StartQueryExecution", "data-lake"),
        ("athena.amazonaws.com", "GetQueryResults", "data-lake"),
        ("s3.amazonaws.com", "GetObject", "data-lake"),
        ("glue.amazonaws.com", "GetTables", "data-lake"),
    ],
    "security": [
        ("securityhub.amazonaws.com", "GetFindings", "account"),
        ("cloudtrail.amazonaws.com", "DescribeTrails", "cloudtrail-main"),
        ("guardduty.amazonaws.com", "ListFindings", "account"),
        ("iam.amazonaws.com", "GetAccountAuthorizationDetails", "account"),
    ],
    "finance": [
        ("ce.amazonaws.com", "GetCostAndUsage", "account"),
        ("budgets.amazonaws.com", "DescribeBudgets", "account"),
    ],
    "ci": [
        ("ecr.amazonaws.com", "PutImage", "production-api"),
        ("ecr.amazonaws.com", "GetAuthorizationToken", "production-api"),
        ("eks.amazonaws.com", "DescribeCluster", "prod-cluster"),
    ],
    "backup": [
        ("rds.amazonaws.com", "CreateDBSnapshot", "payments-db"),
        ("s3.amazonaws.com", "PutObject", "aegis-backups"),
    ],
    "metrics": [
        ("cloudwatch.amazonaws.com", "PutMetricData", "production-api"),
        ("cloudwatch.amazonaws.com", "GetMetricData", "production-api"),
    ],
    "reporting": [
        ("s3.amazonaws.com", "GetObject", "payments-reports"),
        ("s3.amazonaws.com", "PutObject", "payments-reports"),
        ("sts.amazonaws.com", "GetCallerIdentity", "account"),
    ],
    "etl": [
        ("glue.amazonaws.com", "StartJobRun", "data-lake"),
        ("s3.amazonaws.com", "GetObject", "data-lake"),
        ("s3.amazonaws.com", "PutObject", "data-lake"),
    ],
}

# production-api endpoints and who normally calls them
APP_PATHS = {
    "human": [("GET", "/api/v1/orders"), ("GET", "/api/v1/customers/{id}"), ("POST", "/api/v1/orders"),
              ("GET", "/healthz")],
    "reporting": [("GET", "/api/v1/reports/daily"), ("GET", "/api/v1/reports/settlements")],
}
