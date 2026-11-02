# Reference: AWS IAM and CloudTrail for detection engineers

## IAM building blocks
- **Principals**: IAM users (long-lived), IAM roles (assumed, short-lived STS credentials), federated
  users (SSO via SAML/OIDC, show up as `AssumedRole` with a session name), AWS services.
- **Policies**: identity-based (attached to a principal), resource-based (bucket policies, trust
  policies), permission boundaries, Service Control Policies (SCPs - organization-wide guardrails that
  even admins cannot exceed).
- **Evaluation**: an explicit Deny always wins; otherwise an Allow is needed from the relevant policies.

## CloudTrail record anatomy
`eventTime`, `eventSource` (service, e.g. iam.amazonaws.com), `eventName` (API call), `userIdentity`
(who - type, arn, accessKeyId, sessionContext.mfaAuthenticated), `sourceIPAddress`, `userAgent`,
`requestParameters`, `responseElements`, `errorCode` (AccessDenied etc.), `readOnly`.
Management events (control plane) are logged by default; data events (S3 GetObject, Lambda Invoke) must
be enabled explicitly - without them, bucket exfiltration is invisible.

## High-signal CloudTrail events
- IAM writes: AttachUserPolicy, AttachRolePolicy, PutRolePolicy, CreateUser, CreateAccessKey,
  UpdateAssumeRolePolicy, CreatePolicyVersion.
- Logging changes: StopLogging, DeleteTrail, PutEventSelectors, DeleteFlowLogs, DeleteDetector.
- Secrets: GetSecretValue bursts, ListSecrets from unusual identities.
- Compute: RunInstances with unusual types/regions, CreateFunction with privileged roles.
- Recon: many AccessDenied errors, GetAccountAuthorizationDetails, ListRoles from non-admin principals.

## Credential best practices
- Prefer roles and short-lived credentials over IAM users with access keys.
- Require MFA for console users and sensitive role assumption (`aws:MultiFactorAuthPresent`).
- Restrict where credentials can be used: `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpce`.
- Revoke role sessions by denying tokens issued before a timestamp (`aws:TokenIssueTime`).
