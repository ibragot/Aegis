# Playbook: Brute force and password spraying

## Recognizing the pattern
- **Password guessing (T1110.001)**: many failures against ONE account in a short time (AEG-AUTH-001).
- **Password spraying (T1110.003)**: a few attempts each against MANY accounts from one source, staying
  below lockout thresholds (AEG-AUTH-002). Usernames that do not exist in the directory are a strong
  spraying indicator - the attacker works from a guessed or leaked list.
- **Credential stuffing (T1110.004)**: username/password pairs from other breaches, often distributed
  across many IPs.
The critical signal is a **success after failures** (AEG-AUTH-003): the guess worked.

## Triage
- Which accounts succeeded from the attacking source? Those are compromised.
- Was MFA satisfied on the successful login? A success without MFA on an MFA-required account means a
  policy gap.
- What did the account do after logging in? Enumeration calls (ListUsers, ListRoles,
  GetAccountAuthorizationDetails, T1087.004) indicate the attacker is mapping permissions.

## Containment
1. Block the source IP / ASN at the identity provider and WAF.
2. For every account that authenticated successfully: disable, revoke sessions, reset password,
   re-enroll MFA.
3. Force a password reset for accounts that had failures if the password policy is weak.

## Hardening
- Enforce phishing-resistant MFA (FIDO2/WebAuthn) for every user; MFA defeats almost all spraying.
- Block legacy authentication protocols that cannot do MFA.
- Use smart lockout / risk-based authentication that considers source reputation.
- Alert on authentication from hosting-provider IP ranges (AEG-AUTH-007).
