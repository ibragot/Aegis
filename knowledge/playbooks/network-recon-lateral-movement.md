# Playbook: Internal reconnaissance and lateral movement

## Signals
- One internal host contacting many distinct ports on other hosts (AEG-NET-001, T1046 Network Service
  Discovery). Many REJECTed flows indicate scanning against security groups.
- SSH (22/tcp) fan-out between hosts that are managed through SSM and never use SSH
  (AEG-NET-003, T1021.004 Remote Services: SSH).
- New east-west connections that do not exist in the baseline (the ML engine's `distinct_ports_2m` and
  `new_resource` features).

## Triage
- What runs on the source host and who has access to it? Batch workers and CI runners that execute
  untrusted code are common footholds.
- Did any of the scanned services accept connections? ACCEPTed flows to sensitive ports (databases,
  admin interfaces) need follow-up on the destination.

## Containment
1. Quarantine the source host: replace its security groups with a deny-all "quarantine" group (keeps the
   instance running for forensics, cuts it off from the network).
2. Capture memory and disk for forensics before terminating.
3. Review SSH authorized_keys and recent logins on any destination that accepted connections.

## Prevention (zero trust networking)
- Micro-segmentation: security groups and Kubernetes NetworkPolicies that allow only required flows.
- No direct SSH; use SSM Session Manager with logging.
- Treat the internal network as hostile - authenticate and authorize every service-to-service call (mTLS).
