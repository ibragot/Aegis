# Playbook: IAM privilege escalation and persistence in AWS

## Common escalation paths
- Attaching a managed admin policy to oneself or a role one can assume
  (`AttachUserPolicy`, `AttachRolePolicy` with `AdministratorAccess`) - T1098.003 Account Manipulation:
  Additional Cloud Roles. Detected by AEG-IAM-001.
- Writing an inline policy with `"Action": "*"` (`PutUserPolicy`, `PutRolePolicy`).
- Updating a role's trust policy so an attacker principal can assume it (`UpdateAssumeRolePolicy`).
- `iam:PassRole` combined with service creation (Lambda, EC2, Glue) to run code as a more privileged role.
- Creating a new policy version and setting it as default (`CreatePolicyVersion --set-as-default`).

## Persistence techniques
- New IAM users with console passwords or access keys (`CreateUser`, `CreateLoginProfile`,
  `CreateAccessKey`) - T1136.003 Create Account: Cloud Account. Detected by AEG-IAM-002.
- Extra access keys on existing users (every user can have two).
- Backdoored trust policies and federation providers.

## Investigation steps
1. List every IAM write in the incident window (CloudTrail `eventSource = iam.amazonaws.com`,
   `readOnly = false`).
2. For each new credential, search CloudTrail for its `accessKeyId` - was it used, and from where?
3. Use IAM Access Analyzer and `GetAccountAuthorizationDetails` to diff permissions against the
   infrastructure-as-code baseline (Terraform state).

## Containment and recovery
- Detach the admin policy and delete attacker-created users, keys and policy versions.
- Revert trust-policy changes from version control.
- Apply a Service Control Policy (SCP) that denies `iam:Attach*Policy`, `iam:Put*Policy`,
  `iam:CreateUser`, `iam:CreateAccessKey` except for the deployment pipeline role. This turns a whole
  class of escalation into a blocked API call instead of an incident.

## Least privilege reminders
Grant only the actions a workload needs, scoped to specific resources, with conditions (source VPC, MFA,
tags). Review unused permissions with IAM Access Analyzer's unused-access findings.
