# Validator Troubleshooting

Use this runbook when validator alerts or telemetry snapshots flag problems.
Each section includes immediate diagnostics, recommended fixes, and pointers to
configuration relevant to the failure. Review the
[Validator Quickstart](./validator_quickstart.md) to validate baseline
configuration before diving into incident-specific steps. The quickstart also
includes an endpoint quick-reference table covering `/p2p/peers`,
`/snapshots/*`, and `/state-sync/session` so you can quickly locate data sources
mentioned below. Note that all RPC calls in this quick-reference require the
configured bearer token when RPC auth is enabled.

Snapshot and reconstruction calls return structured error codes. When an RPC
response includes a `code` value, map it to the remediation steps in the
[Snapshot and state sync RPC errors](interfaces/rpc/README.md#snapshot-and-state-sync-rpc-errors)
table before escalating.

## VRF Mismatch or Invalid Proofs

**Symptoms**

- Telemetry emits `telemetry.handshake` warnings referencing VRF signature
  validation failures.
- `/status/rollout` reports `vrf_metrics` rejections increasing steadily.
- Peers disconnect during libp2p handshakes because the advertised VRF payload
  does not match the validator key registered on-chain.

**Diagnostics**

1. Confirm the node is loading the expected VRF key:
   ```sh
   jq '.vrf_key_path' /etc/rpp/node.toml
   sha256sum /etc/rpp/keys/vrf.toml
   ```
2. Compare the public key advertised in `/p2p/peers/self` (or the entry for
   this node inside `/p2p/peers`) with the registry entry configured for the
   validator.
3. Review the latest telemetry snapshot (log target `telemetry`) for the
   `vrf_public_key` field to catch formatting or encoding issues.

**Resolution**

- Replace the `vrf_key_path` file with the correct secret and restart the node.
- Ensure `rollout.feature_gates.consensus_enforcement` remains enabled; disabling
  it hides consensus proof errors but also prevents the runtime from rejecting
  invalid blocks.
- If the validator recently rotated VRF keys, update the on-chain registry so
  other validators accept the new payloads.

## Missing or Stale Snapshots

**Symptoms**

- Telemetry snapshots report `snapshot_height` lagging far behind the latest
  block height.
- `/status/rollout` shows `reconstruction` feature gate enabled but peers cannot
  request reconstruction chunks from this validator.
- Disk usage on the snapshot volume is unexpectedly low after pruning.

**Diagnostics**

1. Validate the configured snapshot directory:
   ```sh
   jq '.snapshot_dir' /etc/rpp/node.toml
   ls -alh /var/lib/rpp/snapshots
   ```
2. Inspect node logs for `snapshot` or `reconstruction` warnings indicating the
   archive task failed to persist the latest state.
3. If the node was restarted recently, ensure the process has write permissions
   to the snapshot path and that the volume is not mounted read-only.

**Resolution**

- Restore snapshots from another validator or a recent backup if the directory
  is empty.
- Increase disk capacity for `snapshot_dir` and `proof_cache_dir` when telemetry
  shows utilisation consistently above 80%.
- Keep `rollout.feature_gates.reconstruction` enabled so the runtime continues
  to publish reconstruction data.
- When consumers report stalled resumes, follow the
  [network snapshot failover runbook](runbooks/network_snapshot_failover.md) to
  restart providers, replay missing chunks, and confirm telemetry has recovered.

## Telemetry Not Emitting

**Symptoms**

- Dashboards stop receiving updates even though the node remains in the validator set.
- `telemetry.rollout` log entries cease, and `/status/rollout` shows telemetry as
  disabled.
- The OTLP collector does not receive new spans from `rpp-node`.

**Diagnostics**

1. Verify telemetry toggles in the configuration:
   ```sh
   jq '.rollout.telemetry' /etc/rpp/node.toml
   ```
2. Test connectivity to the OTLP collector using `curl` or `grpcurl` to rule out
   network ACL issues.
3. Check the process flags to ensure `--telemetry-endpoint` matches the
   configuration and does not override it with an empty string.

**Resolution**

- Set `rollout.telemetry.enabled = true` and provide a valid `endpoint` before
  restarting the node. An empty endpoint only logs telemetry locally.
- Reduce `sample_interval_secs` if the collector expects higher-frequency
  snapshots and confirm the host clock is accurate to avoid timestamp drift.
- Monitor the collector for rate-limit responses; if observed, add retry/backoff
  configuration or provision dedicated telemetry infrastructure.

## Snapshot Catch-up After Rebuilds

**Scenario**: A validator was rebuilt from scratch and now trails the cluster by
hundreds of blocks.

**Remediation**

1. Copy recent `snapshot_dir` and `proof_cache_dir` contents from another
   healthy validator.
2. Start the node with `--config` pointing to the restored directories and
   monitor `/snapshots/jobs` or `/state-sync/session` (include the bearer token
   when RPC auth is configured) to ensure chunks stream successfully.
3. Keep `rollout.feature_gates.pruning` enabled so old state is trimmed only
   after the validator catches up, preventing disk exhaustion.

If catch-up stalls, review the [Deployment & Observability Playbook](./deployment_observability.md)
for additional health probes and escalate with the operations team.

## When to Escalate

Contact the release manager or on-call engineer when:

- VRF mismatches persist after rotating keys and confirming registry entries.
- Snapshots fail to advance despite adequate disk space and correct permissions.
- Telemetry outages last longer than two sampling intervals and the collector
  remains reachable.

Include the relevant configuration excerpts from `config/node.toml`, the
currently enabled feature gates, and recent telemetry logs in the escalation
report. These details accelerate triage and confirm that validator changes align
with the latest [release notes](../RELEASE_NOTES.md).
