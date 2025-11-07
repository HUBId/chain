# Admission policy updates

This runbook captures the operator workflow for editing the network admission
allowlist and blocklist.

## Dual-approval workflow

High-impact changes (any modification to the allowlist or blocklist) require
sign-off from both the operations and security rotations. The RPC endpoint
`POST /p2p/admission/policies` rejects requests that are missing either role and
returns a `400` with a descriptive error string. The peerstore verifies the same
roles before persisting the snapshot, so manual writes or legacy tooling cannot
skip the policy guardrail.【F:rpp/rpc/src/routes/p2p.rs†L158-L263】【F:rpp/p2p/src/peerstore.rs†L1084-L1389】

Include the approvals explicitly in the payload:

```json
{
  "actor": "ops.oncall",
  "reason": "rotate unhealthy validator",
  "allowlist": [{"peer_id": "12D3KooWRpcPeer", "tier": "Tl3"}],
  "blocklist": [],
  "approvals": [
    {"role": "operations", "approver": "ops.oncall"},
    {"role": "security", "approver": "sec.oncall"}
  ]
}
```

If the update is rejected because a peer appears in both lists or one of the
approval roles is missing, capture the HTTP response body in the incident log.
Re-submit the request after fixing the payload.

## Audit expectations

Every successful or rejected attempt is written to the admission audit log with
the actor, approvals, and reason. Review the log via `GET /p2p/admission/audit`
when confirming a change during incident response or scheduled maintenance.
