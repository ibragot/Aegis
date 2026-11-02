# Playbook: Kubernetes workload and cluster compromise

## Signals
- Forbidden (403) requests for secrets from a workload's service account - the pod is probing what its
  token can read (AEG-K8S-004, T1613 Container and Resource Discovery).
- Pods created with `privileged: true`, `hostPath` volumes, `hostPID` or `hostNetwork` - these break
  container isolation and allow escape to the node (AEG-K8S-001, T1611 Escape to Host).
- `kubectl exec` into containers (AEG-K8S-002, T1609 Container Administration Command).
- ClusterRoleBindings or RoleBindings referencing `cluster-admin` (AEG-K8S-003, T1098) - full control of
  the cluster, typically used for persistence.

## Triage
- Which service account made the calls, and which pod/deployment uses it?
- Is the image of the originating pod expected? Was the application exploited (RCE) or was a token stolen?
- From the node: are there unexpected processes, containers or mounts? (A hostPath `/` mount gives root
  on the node, which on EKS can expose the node's IAM instance role.)

## Containment
1. Delete the malicious pods and bindings; cordon and drain affected nodes, then replace them
   (nodes are cattle - rebuild rather than clean).
2. Rotate the service-account tokens and any Kubernetes secrets the attacker could read.
3. If node IAM credentials may have been exposed, rotate them and review CloudTrail for the node role.

## Hardening
- Enforce Pod Security Admission `restricted` on application namespaces (blocks privileged and hostPath
  pods).
- Set `automountServiceAccountToken: false` for workloads that do not call the API.
- Use least-privilege RBAC; never bind application service accounts to cluster-admin.
- Use NetworkPolicies (default-deny) so a compromised pod cannot reach the API server or other services.
- On EKS use IRSA / Pod Identity instead of node instance roles for AWS access, and block pod access
  to the instance metadata service (IMDSv2 with hop limit 1).
