# Admission policy updates

This runbook captures the operator workflow for editing the network admission
allowlist and blocklist.

## Dual-approval workflow

High-impact changes (any modification to the allowlist or blocklist) require
sign-off from both the operations and security rotations. Operators stage a
change with `POST /p2p/admission/policies/pending`, which records the
operations approval and returns a pending identifier. The dual-control service
keeps the snapshot out of the live access lists until security confirms the
request via `POST /p2p/admission/policies/pending/:id/approve`. Both endpoints
validate roles and forward the final approvals to the peerstore so manual
writes or legacy tooling cannot bypass the guardrail.【F:rpp/rpc/src/routes/p2p.rs†L470-L660】【F:rpp/p2p/src/admission/dual_control.rs†L17-L152】【F:rpp/p2p/src/peerstore.rs†L1069-L1545】

Example (operations stage the request, security approves it):

```sh
curl -X POST -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     -H 'Content-Type: application/json' \
     ${RPP_RPC_URL}/p2p/admission/policies/pending \
     -d '{
           "actor": "ops.oncall",
           "reason": "rotate unhealthy validator",
           "allowlist": [{"peer_id": "12D3KooWRpcPeer", "tier": "Tl3"}],
           "blocklist": [],
           "approvals": [
             {"role": "operations", "approver": "ops.oncall"}
           ]
         }'

curl -X POST -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     -H 'Content-Type: application/json' \
     ${RPP_RPC_URL}/p2p/admission/policies/pending/${PENDING_ID}/approve \
     -d '{"approver": "sec.oncall"}'
```

If either call rejects the payload—for example a duplicate peer or a missing
approval—capture the HTTP response body in the incident log and re-submit after
fixing the payload.

## Audit expectations

Every successful or rejected attempt is written to the admission audit log with
the actor, approvals, and reason. Review the log via `GET /p2p/admission/audit`
when confirming a change during incident response or scheduled maintenance.

## Backups and restores

The peerstore writes a timestamped JSON snapshot to
`network.admission.backup_dir` whenever the policies change. Retention is
enforced according to `network.admission.backup_retention_days`, so older
archives are pruned automatically. Use `GET /p2p/admission/backups` to list the
available snapshots and append `?download=<name>` to download a specific
archive.【F:rpp/p2p/src/peerstore.rs†L1090-L1157】【F:rpp/rpc/src/routes/p2p.rs†L90-L225】

For day-to-day operations rely on the CLI wrapper, which applies the validator
configuration automatically:

```sh
# List available snapshots
rpp-node validator admission backups list

# Download the newest snapshot to disk
rpp-node validator admission backups download --backup "${BACKUP}" --output /tmp/admission.json

# Restore a snapshot with the standard dual approvals
rpp-node validator admission restore \
  --backup "${BACKUP}" \
  --actor ops.oncall \
  --reason "rollback to previous allowlist" \
  --approval operations:ops.oncall \
  --approval security:sec.oncall
```

Restores are audited like regular policy updates. After the RPC call returns,
confirm the change via `GET /p2p/admission/policies` and attach the retrieved
backup to the incident record.

## Signed attestations and verification

Admission policy snapshots and every audit log entry are signed with the active
admission signing key declared under `network.admission.signing` in the node
configuration. The peerstore rehydrates unsigned snapshots at startup and
persists the canonical JSON together with a signature so operators can prove
the provenance of every allowlist and audit artifact.【F:rpp/p2p/src/peerstore.rs†L1206-L1260】

Use the validator CLI to verify both the live snapshot and a configurable
window of audit entries against the trusted public keys shipped with the node
configuration:

```sh
rpp-node validator admission verify --audit-limit 100
```

The command fetches the current policies and audit history via RPC, rebuilds
the canonical payload, and validates each signature before reporting success or
failing fast with a descriptive error.【F:rpp/node/src/main.rs†L1023-L1144】 Make
the verification step part of reconciliations and change reviews so incident
notes include proof that the data under inspection was produced by the signing
key currently in rotation.

## Signing key rotation

Store the admission signing key in the medium mandated by the deployment
profile (filesystem, HSM, or Vault). The node expects an Ed25519 secret in the
same TOML format as other key material and derives the public key for the trust
store during startup.【F:rpp/p2p/src/policy_signing.rs†L76-L161】 Rotate the key on
the cadence agreed with security (monthly for production) and follow the steps
below:

1. Generate a fresh Ed25519 signing key and update the trust store map in
   `network.admission.signing.trust_store` with the new public key while keeping
   the previous entries so historical signatures remain verifiable.【F:rpp/runtime/config.rs†L940-L1005】
2. Point `network.admission.signing.key_path` (or the equivalent HSM identifier)
   to the new secret and update `active_key` to the matching identifier.【F:rpp/runtime/config.rs†L952-L1005】
3. Restart the validator. On boot the peerstore will re-sign the snapshot with
   the active key and continue signing audit entries automatically.【F:rpp/p2p/src/peerstore.rs†L699-L758】
4. Run `rpp-node validator admission verify` and attach the CLI output to the
   change ticket as evidence that the new key is active and trusted.

Retire obsolete keys from the trust store only after the signed artifacts have
aged out of retention so operators can still verify historical admissions.

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
