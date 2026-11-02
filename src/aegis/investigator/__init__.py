"""AI Investigator: incident -> context (alerts, events, graph, RAG docs) -> LLM -> report."""

from __future__ import annotations

import logging

from aegis.config import Settings, get_settings
from aegis.investigator.context import build_context
from aegis.investigator.llm import LLMInvestigator
from aegis.investigator.rag import Retriever
from aegis.investigator.template import template_report
from aegis.observability import metrics
from aegis.schema import Incident, InvestigationReport
from aegis.storage.db import Repository

log = logging.getLogger(__name__)

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class Investigator:
    def __init__(self, repo: Repository, settings: Settings | None = None, llm: LLMInvestigator | None = None):
        self.settings = settings or get_settings()
        self.repo = repo
        self.retriever = Retriever(self.settings.knowledge_dir)
        self.llm = llm or LLMInvestigator(self.settings)

    def should_investigate(self, incident: Incident) -> bool:
        if LEVEL_ORDER[incident.risk_level] < LEVEL_ORDER[self.settings.investigate_min_level]:
            return False
        latest = self.repo.latest_report(incident.incident_id)
        # Re-investigate only when the incident has grown since the last report.
        return latest is None or latest[1] < len(incident.alert_ids)

    def investigate(self, incident: Incident, use_llm: bool = True) -> InvestigationReport:
        context = build_context(self.repo, incident, self.retriever)
        report = self.llm.investigate(context) if use_llm else None
        if report is None:
            report = template_report(context)
        self.repo.save_report(report, alert_count=len(incident.alert_ids))
        metrics.INVESTIGATIONS.labels("llm" if report.generated_by != "template" else "template").inc()
        log.info("incident %s investigated by %s", incident.incident_id, report.generated_by)
        return report
