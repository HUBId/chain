# Admission Control Overview

The networking stack validates remote peers twice before they can affect
state: during the initial handshake and every time a gossip message arrives.
This document captures the hardening introduced to make both stages tier-aware
and observable.

## Handshake validation

`Peerstore::record_handshake` rejects peers that violate the access lists or
present inconsistent tier claims. The handler now returns a
`HandshakeOutcome` describing the decision, logs it via `telemetry.handshake`,
and persists the peer record only when the handshake is accepted.【F:rpp/p2p/src/peerstore.rs†L503-L585】

The outcome distinguishes between blocklisted peers, allowlist tier
mismatches, missing public keys or signatures, and VRF verification failures.
Successful handshakes carry an `allowlisted` flag so observability pipelines
can differentiate mandatory peers from opportunistic connections.

## Gossip tier filtering

Incoming gossip messages are filtered through `gossip::evaluate_publish`,
which wraps `AdmissionControl::can_remote_publish`. The helper records the
per-topic decision, emits structured telemetry under `telemetry.gossip`, and
propagates `AdmissionError` when a peer lacks the required tier.【F:rpp/p2p/src/gossip/mod.rs†L1-L39】【F:rpp/p2p/src/swarm.rs†L1547-L1612】

The swarm continues to reward successful publishers and penalise rejected
peers, but the tier check now happens in a single place so metrics and logs
share the same vocabulary.

## Metrics

`AdmissionMetrics` exposes counters for handshake and gossip outcomes. Both
handlers increment the counters with labels covering the decision, the peer's
tier, and rejection reasons. When the `metrics` feature is disabled the calls
become no-ops, so the instrumentation does not affect non-observability
builds.【F:rpp/p2p/src/metrics.rs†L1-L147】

## Managing admission policies

Operators can query and update the persisted allowlist/blocklist through the
authenticated RPC endpoints `GET /p2p/admission/policies` and
`POST /p2p/admission/policies`. Both endpoints require the standard bearer token
when RPC auth is enabled and the peerstore emits structured audit telemetry for
every mutation, including the actor and optional reason.【F:rpp/rpc/src/routes/p2p.rs†L126-L209】【F:rpp/p2p/src/peerstore.rs†L1007-L1189】

### Fetching the active policies

```sh
curl -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     https://rpc.example.org/p2p/admission/policies
```

The response mirrors the peerstore: allowlist entries return the peer ID and
enforced tier, while `blocklist` is sorted to make diffs readable. Persisted
state survives restarts because the peerstore writes the snapshot atomically
before acknowledging the request.【F:rpp/rpc/src/routes/p2p.rs†L126-L157】【F:rpp/p2p/src/peerstore.rs†L907-L937】

### Audited updates

Updates must provide an `actor` string and may include a free-form `reason`.
High-impact mutations—anything that alters the allowlist or blocklist—now
require explicit approvals from both operations and security. The RPC handler
rejects requests that omit either role or reuse the same approver twice and the
peerstore double-checks the approvals before persisting the snapshot so manual
changes cannot bypass the policy.【F:rpp/rpc/src/routes/p2p.rs†L158-L263】【F:rpp/p2p/src/peerstore.rs†L1084-L1389】
On success the updated policies are returned so operators can verify what was
persisted without issuing a second call.

```sh
curl -X POST -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     -H 'Content-Type: application/json' \
     https://rpc.example.org/p2p/admission/policies \
     -d '{
           "actor": "ops.oncall",
           "reason": "replace unhealthy peer",
           "allowlist": [{"peer_id": "12D3KooWRpcPeer", "tier": "Tl3"}],
           "blocklist": ["12D3KooWBannedPeer"],
           "approvals": [
             {"role": "operations", "approver": "ops.oncall"},
             {"role": "security", "approver": "sec.oncall"}
           ]
         }'
```

If the payload is invalid—for example the same peer appears twice or a required
approval is missing—the service returns a `400` with a descriptive error string
so auditors can capture the failed attempt in their runbooks.【F:rpp/rpc/src/routes/p2p.rs†L172-L263】

### Inspecting the audit log

Every policy mutation (including no-op attempts) is appended to an
append-only JSONL log alongside the actor, optional reason, timestamp and the
previous/current state of the affected entry. The peerstore writes the log next
to the policy snapshot and surfaces it via `GET /p2p/admission/audit`, which
accepts `offset` and `limit` query parameters for pagination. Each entry records
the peer ID, tier transitions for allowlist edits, or blocklist toggles so
operators can reconstruct the full history.【F:rpp/p2p/src/peerstore.rs†L1045-L1175】【F:rpp/p2p/src/policy_log.rs†L1-L112】【F:rpp/rpc/src/routes/p2p.rs†L110-L153】

```sh
curl -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     'https://rpc.example.org/p2p/admission/audit?offset=0&limit=50'
```

The RPC response reports the total number of entries, the requested window, and
the selected slice. Operators should size retention according to
`network.admission.audit_retention_days` in the config bundle; the peerstore
keeps writing to the JSONL file while external rotation jobs enforce the
window.【F:rpp/runtime/config.rs†L942-L1004】【F:docs/configuration.md†L48-L50】

To guard against regressions, the test
`dual_approval_update_records_audit_approvals` performs a full RPC update with
operations and security approvals and verifies that the audit log encodes both
approver records. Run it locally with:

```sh
cargo test -p rpp-chain --locked --test admission -- \
  dual_approval_update_records_audit_approvals
```

### Policy backups and restores

Every successful policy mutation also emits a timestamped snapshot in the
directory configured by `network.admission.backup_dir`. The peerstore keeps the
most recent backups that fall within the
`network.admission.backup_retention_days` window and automatically prunes older
archives.【F:rpp/p2p/src/peerstore.rs†L1090-L1157】【F:rpp/runtime/config.rs†L972-L1004】

Operators can list available snapshots via `GET /p2p/admission/backups`. Passing
`?download=<name>` streams the requested archive so it can be copied off-box or
fed into change reviews. Restoring a snapshot uses `POST /p2p/admission/backups`
with the backup name, the acting operator, optional reason, and dual approvals;
the restore is audited like any other mutation.【F:rpp/rpc/src/routes/p2p.rs†L90-L225】

```sh
# enumerate available backups
curl -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     ${RPP_RPC_URL}/p2p/admission/backups | jq .

# download a specific archive
curl -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     "${RPP_RPC_URL}/p2p/admission/backups?download=${BACKUP}" \
     -o "${BACKUP}"

# restore with the same dual-approval workflow used for edits
curl -X POST -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     -H 'Content-Type: application/json' \
     ${RPP_RPC_URL}/p2p/admission/backups \
     -d "{\n       \"backup\": \"${BACKUP}\",\n       \"actor\": \"ops.oncall\",\n       \"reason\": \"roll back to audited state\",\n       \"approvals\": [\n         {\"role\": \"operations\", \"approver\": \"ops.oncall\"},\n         {\"role\": \"security\", \"approver\": \"sec.oncall\"}\n       ]\n     }"
```

The `rpp-node` CLI mirrors these endpoints through
`validator admission backups list|download|restore`, which automatically applies
the configured RPC URL and bearer token from the validator profile so on-call
operators can audit and recover policies without crafting manual payloads.【F:rpp/node/src/main.rs†L151-L408】

## Tests

`tests/network/admission_control.rs` exercises the new failure modes: a peer
failing to meet its allowlist tier is rejected during the handshake, and a
valid tier-two peer attempting to publish consensus votes hits the expected
`TierInsufficient` error.【F:tests/network/admission_control.rs†L1-L92】
