# Playbook: Resource hijacking (crypto-mining) and unauthorized compute

## Signals
- `RunInstances` with GPU or very large instance types (p*, g*, x*, inf*, trn*) by an identity that
  never launches compute (AEG-RES-001, T1496 Resource Hijacking).
- Instances launched in unusual regions, or in production subnets by non-deployment identities.
- Privileged containers launched with miner images, high CPU, connections to mining pools on
  ports 3333/4444/5555/14444.

## Response
1. Snapshot the instance volumes (evidence), then stop/terminate the instances.
2. Identify the credential used and follow the cloud credential compromise playbook.
3. Check every region - attackers often launch in regions you do not monitor.
4. Contact the cloud provider's support if the bill impact is large.

## Prevention
- SCPs restricting allowed regions and instance types.
- Service Quotas set low for GPU families you do not use.
- Budgets and cost-anomaly alerts as a last line of detection.
