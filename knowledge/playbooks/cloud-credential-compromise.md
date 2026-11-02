# Playbook: Cloud credential / service-account compromise

## When to use
Use this playbook when a cloud identity (IAM user, role session, service account, OAuth client) is used
by someone other than its owner. Typical triggers: a service account authenticating from outside the
VPC (AEG-AUTH-006), a login from a never-seen country (AEG-AUTH-004, T1078 Valid Accounts), a privileged
session without MFA (AEG-AUTH-005, T1078.004 Cloud Accounts), or a successful login right after repeated
failures (AEG-AUTH-003).

## Why service accounts are high-value targets
Service accounts are machine identities. They usually hold broad, long-lived permissions, have no MFA,
and their secrets end up in CI variables, config files, container images and git history. Their
behaviour is extremely regular (same source IP, same API calls, around the clock), which makes deviations
easy to spot: any interactive login, any new country, any new API family is suspicious.

## Triage questions
- Did the credential authenticate from an address outside the expected network ranges?
- Is the source a hosting provider, VPN or Tor exit rather than corporate infrastructure?
- Did the session obtain privileges it does not normally use (AssumeRole into an admin role)?
- Did the identity perform IAM writes, create resources, or read secrets after the login?
- Was the same source IP used against other identities?

## Containment
1. Revoke active sessions: for IAM roles attach a policy denying actions for tokens issued before now
   (`aws:TokenIssueTime` condition); for the IdP revoke refresh tokens.
2. Disable and rotate the credential: deactivate access keys, rotate the OAuth client secret, rotate any
   secret the identity could read.
3. Block the attacker source IPs at the IdP, WAF and network firewall.
4. If the identity created other credentials (CreateUser, CreateAccessKey, CreateLoginProfile), disable
   those too - this is the attacker's persistence.

## Eradication and recovery
- Remove every permission change made during the incident window (attached policies, trust policy
  changes, new roles).
- Terminate unauthorized resources after preserving forensic copies (EBS snapshots, pod logs).
- Re-issue the service account's credential through the secrets manager and redeploy consumers.
- Restrict where the credential can be used from: VPC endpoint policies, `aws:SourceVpc`,
  `aws:SourceIp` conditions, IdP network zones.

## Detection improvements
- Alert on any service-account authentication from outside the VPC CIDR.
- Baseline per-identity API usage and alert on new API families (the Aegis ML engine does this).
- Prefer short-lived credentials (IAM Roles for Service Accounts / workload identity federation) over
  static keys.
