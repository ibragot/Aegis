# Reference: MITRE ATT&CK techniques used by Aegis detections

## How ATT&CK is organized
MITRE ATT&CK describes attacker behaviour as **tactics** (the goal - the "why", e.g. Privilege
Escalation) and **techniques** (the method - the "how", e.g. T1098.003 Additional Cloud Roles). Tactics
roughly follow a kill chain: Reconnaissance, Resource Development, Initial Access, Execution,
Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement,
Collection, Command and Control, Exfiltration, Impact. An incident that moves forward through several
tactics is far more likely to be a real intrusion than a single isolated signal - which is why Aegis
adds risk for tactic breadth and kill-chain progression.

## T1078 Valid Accounts / T1078.004 Cloud Accounts
Adversaries use legitimate credentials to log in, bypassing controls that look for malware. Detect with
behavioural baselines: new country, new IP/ASN, impossible travel, hosting-provider sources, unusual
hours, privileged sessions without MFA.

## T1110 Brute Force (T1110.001 Password Guessing, T1110.003 Password Spraying)
Repeated authentication attempts. Spraying spreads attempts across many accounts to avoid lockouts.

## T1098 Account Manipulation / T1098.003 Additional Cloud Roles
Modifying permissions or credentials of accounts to keep or elevate access: attaching admin policies,
adding role bindings, adding keys.

## T1136.003 Create Account: Cloud Account
Creating new cloud identities (IAM users, service principals) for persistence.

## T1555.006 Credentials from Cloud Secrets Management Stores
Reading many secrets from AWS Secrets Manager / Parameter Store / Key Vault to harvest credentials.

## T1530 Data from Cloud Storage
Accessing data in object storage (S3 buckets) - often bulk download by a compromised or insider identity.

## T1213 Data from Information Repositories
Harvesting data from internal applications and APIs (admin export endpoints, wikis, CRMs).

## T1048 Exfiltration Over Alternative Protocol
Moving data out over a channel other than the existing command-and-control channel, often encrypted
HTTPS to attacker-controlled hosting.

## T1562.008 Impair Defenses: Disable or Modify Cloud Logs
Stopping or deleting CloudTrail trails, flow logs or security services to avoid detection.

## T1496 Resource Hijacking
Using victim compute (often GPUs) for crypto-mining.

## T1611 Escape to Host
Breaking out of a container to the underlying node, e.g. via privileged containers or hostPath mounts.

## T1609 Container Administration Command
Running commands inside containers via the orchestration API (`kubectl exec`).

## T1613 Container and Resource Discovery
Enumerating pods, secrets and cluster resources to plan next steps.

## T1046 Network Service Discovery
Scanning hosts and ports to find services to attack.

## T1021.004 Remote Services: SSH
Moving laterally between hosts with SSH using stolen keys or passwords.

## T1087.004 Account Discovery: Cloud Account
Enumerating IAM users, roles and policies (ListUsers, ListRoles, GetAccountAuthorizationDetails).
