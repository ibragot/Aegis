# Playbook: Security logging disabled (defense evasion)

## Signals
`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` (CloudTrail), `DeleteFlowLogs` (VPC),
`DeleteDetector` (GuardDuty), `DisableSecurityHub` - T1562.008 Impair Defenses: Disable or Modify Cloud
Logs. Detected by AEG-DEF-001 at critical severity because legitimate changes to audit logging are rare
and always go through change management.

## Why it matters
Attackers blind defenders before the noisy part of an attack. Everything after this point may be missing
from your logs, so the response must assume the worst about what happened during the gap.

## Immediate actions
1. Re-enable the logging that was disabled (`StartLogging`, recreate flow logs and detectors).
2. Treat the identity that made the change as compromised; revoke its sessions and credentials.
3. Determine the logging gap window and use other sources for it: S3 server access logs, load
   balancer logs, application logs, the organization-level trail, and the Aegis raw-log archive.

## Prevention
- An organization trail managed from a separate security account that member accounts cannot modify.
- SCPs denying `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `ec2:DeleteFlowLogs`,
  `guardduty:DeleteDetector` for everyone except a break-glass role.
- Log file integrity validation and S3 Object Lock on the log bucket.
