# Playbook: Data collection and exfiltration

## Signals
- Bulk object downloads from sensitive buckets (AEG-S3-001, T1530 Data from Cloud Storage). Tools like
  rclone, s3cmd or custom scripts show up in the user agent.
- Bulk export through application admin endpoints (AEG-APP-001, T1213 Data from Information Repositories).
- Large outbound flows from inside the VPC to external hosting providers (AEG-NET-002, T1048 Exfiltration
  Over Alternative Protocol / T1567 Exfiltration Over Web Service).
- Secrets harvesting before exfiltration (AEG-SEC-001, T1555.006).

## Triage
- What data was touched? Map bucket prefixes / endpoints to data classification (customer PII, payment
  data, source code).
- How much left? Sum `bytesTransferredOut` in CloudTrail data events and `bytes` in VPC flow logs for the
  destination.
- Who is the actor - external attacker with stolen credentials, or an insider? Insider exfiltration often
  happens at unusual hours from the user's normal IP with sync tools.

## Containment
1. Block egress to the destination (network firewall / NAT gateway rules, security groups).
2. Remove the actor's access to the data store (bucket policy deny, revoke sessions).
3. Isolate hosts that sent data out.

## Recovery and obligations
- Preserve the logs that prove scope - they drive legal and regulatory decisions.
- Engage legal/privacy: personal data exposure may require notification within fixed deadlines
  (e.g. 72 hours under GDPR).
- Rotate any credentials or keys included in the exfiltrated data.

## Prevention
- S3 Block Public Access, bucket policies restricted to VPC endpoints (`aws:SourceVpce`), and Macie for
  data classification.
- Egress filtering: production subnets should only reach known destinations.
- Data-access logging (S3 data events) must be enabled to investigate this at all.
