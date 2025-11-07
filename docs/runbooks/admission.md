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

## Reconciliation checks

The node runs a background admission reconciler that continuously compares the
in-memory allowlist and blocklist with both the persisted snapshot on disk and
the audit log. The reconciler executes every minute by default and raises
alerts as soon as drift is detected, so you do not need to wait for the next
manual reload to surface inconsistency.

1. Inspect the `rpp.node.admission.policy_drift_detected_total` counter for
   increments. The metric is tagged with `kind="disk"`, `kind="audit"`, or
   `kind="audit_lag"` to highlight whether the snapshot, audit log, or audit
   timestamp is lagging. The reconciler also emits
   `rpp.node.admission.reconcile_total{drift="true"}` when a cycle observes
   mismatched state.
2. When the metric reports `disk` drift, fetch the persisted snapshot from the
   node (`/p2p/admission/policies`) and compare it to the on-disk JSON at the
   path configured by `network.admission.policy_path`. A divergence indicates a
   failed disk write.
3. When `audit` drift is reported, reconcile the audit trail with the live
   policies. Missing entries point to an append failure in the audit log; open
   an incident and freeze admission changes until the log is repaired.
4. A `audit_lag` drift means the disk snapshot is newer than the most recent
   audit entry for longer than the configured threshold. Verify that the audit
   service is healthy and that retention or rotation has not removed recent
   entries.

The reconciler shuts down automatically when the node stops, but it does not
correct drift on its own. Operators should restore the policy snapshot and audit
log before resuming admission changes.
