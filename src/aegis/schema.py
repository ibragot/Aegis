"""The data contracts that flow between every Aegis component.

Five very different log formats (CloudTrail JSON, IdP auth logs, Kubernetes
audit logs, VPC flow logs, application logs) are normalized into ONE `Event`
shape by the collectors. Everything downstream - rules, ML features, the graph,
the correlator - only ever sees `Event`, which is the core idea behind SIEM
schemas such as Elastic ECS, OCSF or Microsoft Sentinel's ASIM.

    Event  --(rules / ml)-->  Alert  --(correlator)-->  Incident  --(investigator)-->  InvestigationReport
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

Source = Literal["cloudtrail", "auth", "k8s_audit", "network", "app"]
Category = Literal["authentication", "iam", "resource", "api", "kubernetes", "network", "application"]
Outcome = Literal["success", "failure", "unknown"]


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class GroundTruth(BaseModel):
    """Label attached by the *simulator* only.

    Detectors must never read this field - it exists so we can measure
    precision / recall of the rules and ML models against known answers.
    """

    malicious: bool = False
    scenario: str | None = None
    stage: str | None = None


class Event(BaseModel):
    event_id: str
    timestamp: datetime
    source: Source
    category: Category
    action: str  # e.g. "ConsoleLogin", "AttachUserPolicy", "create pods", "flow", "GET /admin"
    outcome: Outcome = "unknown"

    # Who did it
    principal: str | None = None  # user / service account / role session
    principal_type: str | None = None  # user | service_account | role | host

    # From where
    src_ip: str | None = None
    geo_country: str | None = None
    geo_city: str | None = None
    user_agent: str | None = None

    # To what
    target_resource: str | None = None
    resource_type: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    bytes_out: int | None = None
    bytes_in: int | None = None

    # Security-relevant flags extracted by the collector
    privileged: bool = False
    mfa: bool | None = None

    attributes: dict[str, Any] = Field(default_factory=dict)
    truth: GroundTruth | None = None

    @property
    def entity_key(self) -> str:
        """The identity whose behaviour this event describes.

        Network flows have no user, so they are attributed to the source IP.
        This key is also the Kafka partition key, which guarantees that all
        events for one identity are processed in order by one consumer.
        """
        return self.principal or self.src_ip or "unknown"


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_WEIGHT = {Severity.low: 10, Severity.medium: 25, Severity.high: 45, Severity.critical: 65}


class EntityRef(BaseModel):
    type: str  # user | ip | resource | role | access_key | pod | country | host
    value: str

    @property
    def id(self) -> str:
        return f"{self.type}:{self.value}"

    def __hash__(self) -> int:  # allow use in sets
        return hash(self.id)


class Mitre(BaseModel):
    tactic: str
    technique_id: str
    technique: str


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: new_id("alr"))
    created_at: datetime = Field(default_factory=utcnow)
    event_time: datetime
    detector: Literal["rules", "ml"]
    rule_id: str
    rule_name: str
    severity: Severity
    score: float = 0.0  # 0..1 confidence / anomaly score
    mitre: Mitre | None = None
    description: str = ""
    entities: list[EntityRef] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScoreFactor(BaseModel):
    factor: str
    points: float
    reason: str


class Incident(BaseModel):
    incident_id: int
    title: str
    status: Literal["open", "investigating", "closed"] = "open"
    risk_score: float
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    score_breakdown: list[ScoreFactor] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    alert_ids: list[str] = Field(default_factory=list)
    entities: list[EntityRef] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)  # in the order they were first observed
    correlation_keys: list[str] = Field(default_factory=list)  # strong entity ids used for merging


class Evidence(BaseModel):
    claim: str
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    action: str
    priority: Literal["immediate", "high", "medium", "low"]
    rationale: str


class InvestigationReport(BaseModel):
    incident_id: int
    generated_by: str  # model id, or "template" for the offline fallback
    generated_at: datetime = Field(default_factory=utcnow)
    summary: str
    what_happened: str
    systems_involved: list[str]
    why_flagged: str
    evidence: list[Evidence]
    recommended_actions: list[RecommendedAction]
    mitre_techniques: list[str]
    confidence: Literal["low", "medium", "high"]
    false_positive_considerations: str
    references: list[str] = Field(default_factory=list)  # knowledge-base chunk ids used (RAG)
