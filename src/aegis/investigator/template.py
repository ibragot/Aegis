"""Deterministic (no-LLM) investigator.

Produces the same report structure as the LLM from the same context using
rules of thumb. It makes Aegis fully usable offline / without an API key and
is a useful baseline to compare the LLM's reports against.
"""

from __future__ import annotations

from aegis.enrichment import asset_criticality
from aegis.schema import Alert, Evidence, InvestigationReport, RecommendedAction

ACTIONS: dict[str, tuple[str, str, str]] = {
    # rule prefix -> (priority, action, rationale)
    "AEG-AUTH-006": ("immediate", "Revoke and rotate the service account's client secret / access keys, and restrict "
                     "its token issuance to the VPC CIDR with a conditional-access policy.",
                     "Machine identities must never authenticate from the internet."),
    "AEG-AUTH-001": ("high", "Reset the account's password, revoke active sessions and confirm MFA enrollment.",
                     "Repeated guessing against one account."),
    "AEG-AUTH-002": ("high", "Block the spraying source at the IdP / WAF and review every account it touched.",
                     "Password spraying targets many accounts at once."),
    "AEG-AUTH-003": ("immediate", "Treat the account as compromised: disable it, revoke sessions and tokens, reset "
                     "credentials.", "A success directly after repeated failures means the guess worked."),
    "AEG-AUTH-004": ("medium", "Confirm the new-country login with the identity owner (travel? VPN?).",
                     "First login from this country for the identity."),
    "AEG-AUTH-005": ("high", "Enforce MFA for privileged roles (IdP policy and aws:MultiFactorAuthPresent "
                     "conditions on admin roles).", "Zero-trust: privileged access always requires MFA."),
    "AEG-IAM-001": ("immediate", "Detach AdministratorAccess from the modified role/user and review its recent "
                    "activity; add an SCP that denies iam:Attach*Policy outside the deployment pipeline.",
                    "Full-admin grants are the fastest privilege-escalation path."),
    "AEG-IAM-002": ("immediate", "Delete attacker-created IAM users and access keys; search CloudTrail for any use "
                    "of the new keys.", "Persistence: new credentials survive a password reset."),
    "AEG-RES-001": ("immediate", "Snapshot the instance's volumes for forensics, then isolate (quarantine security "
                    "group) and terminate it.", "Unapproved GPU compute is typical of crypto-mining."),
    "AEG-SEC-001": ("immediate", "Rotate every secret that was read during the incident window.",
                    "Harvested secrets give the attacker access to downstream systems."),
    "AEG-S3-001": ("high", "Block the identity's access to the bucket, assess which objects left, and start the "
                   "data-exposure / privacy notification process.", "Bulk download from a customer-data bucket."),
    "AEG-APP-001": ("high", "Block the client at the WAF, disable the admin export endpoint for non-VPN sources and "
                    "assess exported records.", "Automated bulk export via admin API."),
    "AEG-NET-002": ("immediate", "Block egress to the destination at the NAT / network firewall and isolate the "
                    "source host.", "Large transfer to hosting-provider infrastructure = likely exfiltration."),
    "AEG-NET-001": ("high", "Quarantine the scanning host and investigate it for malware.", "Internal port scan."),
    "AEG-NET-003": ("high", "Quarantine the source host; review SSH keys on targets.", "SSH fan-out = lateral movement."),
    "AEG-DEF-001": ("immediate", "Re-enable CloudTrail / flow logs / GuardDuty immediately and protect them with an "
                    "SCP; treat the actor as compromised.", "Attackers disable logging before acting."),
    "AEG-K8S-001": ("immediate", "Delete the privileged pod, cordon the node it ran on, and enforce Pod Security "
                    "Admission 'restricted' on the namespace.", "Privileged/hostPath pods allow node escape."),
    "AEG-K8S-002": ("medium", "Confirm the exec session was authorized; review the container for tampering.",
                    "Interactive shells in production are rare."),
    "AEG-K8S-003": ("immediate", "Delete the cluster-admin binding and rotate the bound service account's token.",
                    "cluster-admin = full cluster control."),
    "AEG-K8S-004": ("medium", "Review the workload's service-account RBAC; it is probing for secrets.",
                    "Repeated forbidden secret reads."),
    "AEG-DISC-001": ("medium", "Review what the identity enumerated and scope down its permissions.",
                     "Enumeration precedes privilege escalation."),
    "AEG-ML-001": ("medium", "Review the anomalous activity with the identity's owner.",
                   "Behaviour deviates from the learned baseline."),
}


def template_report(context: dict) -> InvestigationReport:
    inc = context["incident"]
    alerts: list[Alert] = context["_alerts"]
    graph = context["graph"]
    detectors = sorted({a.detector for a in alerts})

    summary = (
        f"Aegis correlated {len(alerts)} alert(s) from the {' and '.join(detectors)} detector(s) into a "
        f"{inc['risk_level']} incident (risk {inc['risk_score']}/100): {inc['title']}."
    )
    if graph.get("pivot"):
        summary += f" The central entity is {graph['pivot']}."

    lines = []
    for a in alerts:
        mitre = f" [{a.mitre.tactic} / {a.mitre.technique_id}]" if a.mitre else ""
        who = ", ".join(e.id for e in a.entities[:3])
        lines.append(f"{a.event_time:%H:%M:%S} - {a.rule_name}{mitre} ({who})")
    what = "Timeline of correlated alerts:\n" + "\n".join(lines)

    systems = sorted({e.split(":", 1)[1] for e in inc["entities"]
                      if e.split(":", 1)[0] in ("resource", "role", "access_key", "host")})[:15]
    systems += [e for e in inc["entities"] if e.startswith("ip:")][:5]

    why = "Signals were grouped because they share entities within the correlation window"
    if len(inc["tactics"]) > 1:
        why += f" and progress through {len(inc['tactics'])} ATT&CK tactics ({' -> '.join(inc['tactics'])})"
    why += ". Score factors: " + "; ".join(f"{f['reason']} (+{f['points']})" for f in inc["score_breakdown"])

    evidence = [Evidence(claim=f"{a.rule_name}: {a.description[:220]}", alert_ids=[a.alert_id],
                         event_ids=a.event_ids[:5]) for a in alerts[:12]]
    if graph.get("attack_paths"):
        p = graph["attack_paths"][0]
        evidence.append(Evidence(claim="Graph path from external infrastructure to a critical asset: " + " -> ".join(p)))

    actions: list[RecommendedAction] = []
    seen = set()
    for a in alerts:
        key = a.rule_id
        if key in ACTIONS and key not in seen:
            seen.add(key)
            prio, act, why_ = ACTIONS[key]
            actions.append(RecommendedAction(action=act, priority=prio, rationale=why_))
    actions.append(RecommendedAction(
        action="Preserve evidence: export the archived raw logs (S3 data lake) and CloudTrail for the incident window "
               "before any cleanup.", priority="high", rationale="NIST 800-61: preserve evidence before eradication."))
    order = {"immediate": 0, "high": 1, "medium": 2, "low": 3}
    actions.sort(key=lambda r: order[r.priority])

    techniques = sorted({f"{a.mitre.technique_id} {a.mitre.technique}" for a in alerts if a.mitre})
    rules_and_ml = {"rules", "ml"} <= set(detectors)
    confidence = "high" if len(inc["tactics"]) >= 3 or (rules_and_ml and len(alerts) >= 3) else (
        "medium" if len(alerts) >= 2 else "low")

    crit = [s for s in systems if asset_criticality(s) == "critical"]
    fp = ("Single-signal incidents are frequently benign (travel, new device, on-call work). "
          if len(alerts) == 1 else
          "Multiple independent signals on the same entities make a benign explanation unlikely, but confirm with "
          "the identity owner and change-management records. ")
    if crit:
        fp += f"Critical assets involved ({', '.join(crit)}) justify containment before confirmation."

    return InvestigationReport(
        incident_id=inc["incident_id"],
        generated_by="template",
        summary=summary,
        what_happened=what,
        systems_involved=systems,
        why_flagged=why,
        evidence=evidence,
        recommended_actions=actions[:10],
        mitre_techniques=techniques,
        confidence=confidence,
        false_positive_considerations=fp,
        references=[d["id"] for d in context["documents"]],
    )
