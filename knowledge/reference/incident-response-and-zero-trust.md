# Reference: Incident response lifecycle and zero trust

## NIST SP 800-61 incident response lifecycle
1. **Preparation** - logging, playbooks, access for responders, communication plans.
2. **Detection and analysis** - alerts are triaged, correlated, scoped; severity assigned.
3. **Containment, eradication and recovery** - stop the bleeding (short-term containment), remove the
   attacker (eradication), restore service safely (recovery).
4. **Post-incident activity** - lessons learned, detection improvements, control changes.
Evidence must be preserved *before* eradication: snapshots, logs, memory images.

## Severity and prioritization
Prioritize by impact and confidence: involvement of critical assets (production, customer data,
identity systems), privilege level of the compromised identity, evidence of an active attacker
(hands-on-keyboard actions, multiple tactics), and data exposure.

## Zero trust principles (NIST SP 800-207)
- Never trust, always verify: authenticate and authorize every request, regardless of network location.
- Least privilege: minimal permissions, just-in-time and just-enough access.
- Assume breach: segment networks, monitor everything, limit blast radius.
- Strong identity: phishing-resistant MFA for people, short-lived workload identities for machines.
- Continuous evaluation: device posture, location and behaviour feed access decisions.

## SIEM concepts
- **Normalization** - map many log formats onto one schema (ECS, OCSF, ASIM).
- **Enrichment** - add context (GeoIP, asset criticality, identity data, threat intel).
- **Detection rules** - signatures, thresholds, sequences, baselines.
- **Correlation** - group related alerts into incidents to fight alert fatigue.
- **Detection-as-code** - rules in version control, tested in CI, reviewed like software.
