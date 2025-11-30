# Mempool Operations

> **Runbook:** See the [mempool cleanup remediation flow](./mempool_cleanup.md)
> for the step-by-step incident response validated by the spam/DoS tests.

The runtime exposes a single transaction mempool that enforces a fixed capacity and emits
gossip events whenever submissions succeed. The integration test `high_volume_spam_triggers_rate_limits_and_recovers`
demonstrates the happy-path behaviour that operators can rely on for incident response.

## Observability

* `/status/mempool` returns the pending transactions, current queue weights, and can be used to
  compute fee-based ordering during investigations. The test captures the highest observed fee and
  validates that custom queue weights surface in the response, mirroring the fields returned by the
  API.【F:tests/mempool/spam_recovery.rs†L63-L88】
* When zk verification is enabled, proposers drain the transaction queue in
  fee-descending order and fall back to the nonce when fees tie, ensuring
  high-fee submissions survive proof verification, mempool replay, and
  reorgs. Integration coverage spans the default backend and an RPP-STARK
  recovery path to confirm ordering holds through partitions.【F:rpp/runtime/node.rs†L8388-L8415】【F:tests/integration/zk_ordering.rs†L1-L122】【F:tests/reorg_rpp_stark.rs†L229-L301】
* `/status/node` exposes the aggregate pending transaction count, allowing dashboards to track the
  backlog as spam ebbs and flows.【F:tests/mempool/spam_recovery.rs†L41-L47】【F:tests/mempool/spam_recovery.rs†L110-L118】
* Uptime-ready probes now submit tiny transactions (or observe mempool readiness) during consensus
  stalls and drop `uptime_mempool_probe_success_ratio` to flag client-facing impact. The signal clears
  once consensus resumes and probes succeed again, providing a canary that the mempool is healthy
  before reopening traffic.【F:tools/alerts/validation.py†L120-L184】【F:tools/alerts/validation.py†L1887-L1969】【F:docs/operations/uptime.md†L37-L49】
* Subscribe to the internal `WitnessProofs` gossip channel to confirm that successful submissions
  emit events containing the transaction hash and fee, which is useful when correlating accepted
  transactions with rate limit tuning.【F:tests/mempool/spam_recovery.rs†L31-L40】【F:tests/mempool/spam_recovery.rs†L96-L105】
* A peer-churn simnet test (`tests/mempool/peer_churn.rs::peer_churn_respects_rate_limits_and_preserves_queue_ordering`) spins
  up rotating gossip subscribers while flooding the mempool across every enabled proof backend. It asserts that rate-limit
  rejections fire once the queue is saturated, that the highest-fee ordering survives churn, and that the alert probe surfaces
  warning/critical signals. On failure, the harness writes `peer-churn.json` to `target/artifacts/mempool-peer-churn`
  (override with `MEMPOOL_PEER_CHURN_ARTIFACT_DIR`) containing accepted/rejected hashes, alert summaries, backend coverage,
  and witness delivery counts for debugging.【F:tests/mempool/peer_churn.rs†L1-L213】
* The `/status/mempool` probe in the integration suite explicitly saturates the queues, verifies that
  warning- and critical-level alerts fire for transactions and identities, and ensures gossip stays
  drained while the probe operates.【F:tests/mempool/status_probe.rs†L77-L163】 Use the same thresholds
  (80% warning, 100% critical by default) when wiring dashboards so that operator alerts align with
  the regression harness.【F:tests/mempool/status_probe.rs†L38-L74】
* The probe now exercises the full recovery loop: raising `mempool_limit`, rebalancing queue weights,
  and restarting with the recovered configuration to confirm alerts clear, queue depth metrics match
  `/status/node`, and the restart surface returns the adjusted weights without firing new alerts.
  Mirror the same steps in production to validate that alert fatigue has been addressed before
  closing an incident.【F:tests/mempool/status_probe.rs†L165-L263】
* A restart probe captures the saturated transaction queue, restores it after a node restart in
  fee-descending order, and persists the observed vs. expected ordering (plus any generated alerts)
  when the test fails to `target/artifacts/mempool-ordering-probe/ordering.json` (or the directory
  set via `MEMPOOL_ORDERING_ARTIFACT_DIR`, collected from CI under
  `artifacts/mempool/<matrix>/ordering`). This guards against regressions where restart flows reorder
  pending work away from fee priority and confirms alerts still fire when the restored queue is
  full.【F:tests/mempool/spam_recovery.rs†L108-L207】【F:.github/workflows/ci.yml†L946-L1004】
* A mixed spam probe floods both transaction and vote queues to validate that rate limiting stays
  scoped per queue (overflowing transactions does not evict votes, and vice versa) and to record
  per-queue eviction counts. Failing runs persist the decoded queue contents, eviction attempts,
  queue weights, and node metrics to `target/artifacts/mempool-eviction-probe/evictions.json` (or
  `artifacts/mempool/<matrix>/eviction` in CI via `MEMPOOL_EVICTION_ARTIFACT_DIR`) so operators can
  audit how many submissions were rejected per class when tuning fairness rules and inspect the
  exact eviction order captured in the transaction and vote queues.【F:tests/mempool/spam_recovery.rs†L210-L305】【F:.github/workflows/ci.yml†L940-L1004】
* The spam saturation probe now writes `spam.json` (guarded by `MEMPOOL_SPAM_ARTIFACT_DIR`, defaulting
  to `target/artifacts/mempool-spam-probe/`) on failures, capturing accepted hash/fee pairs, pending
  queue depths before and after recovery, recovered queue order, and the number of overflow
  submissions rejected. CI collects the same payloads under `artifacts/mempool/<matrix>/spam` to aid
  root-cause analysis when rate-limit regressions trip the test.【F:tests/mempool/spam_recovery.rs†L18-L164】【F:.github/workflows/ci.yml†L940-L1004】
* Spam/DoS probes rotate submissions across every enabled proof backend (STWO, Plonky3, and
  backend-rpp-stark) to ensure mixed node populations preserve acceptance, eviction ordering,
  restart semantics, and alert payloads regardless of which zk stack is active. CI exercises the
  `mixed-backend-rpp-stark` integration matrix to pin coverage for rpp-stark deployments alongside
  the default backend.【F:tests/mempool/spam_recovery.rs†L63-L233】【F:tests/mempool/status_probe.rs†L63-L183】【F:.github/workflows/ci.yml†L928-L973】

### Interpreting probe alerts

* **Warning alarms (≥80%).** Treat the warning as a heads-up that a queue is approaching saturation.
  The probe expects transaction warnings to coexist with other queues, so investigate fee pressure or
  round restarts before the backlog spills over.【F:tests/mempool/status_probe.rs†L117-L149】
* **Critical alarms (≥100%).** The probe enqueues enough entries to trip critical alerts on
  transactions and identities, ensuring the alerting pipeline is wired. When the runtime emits the
  same signal in production, immediately pause bulk submissions and either raise `mempool_limit` or
  drain stuck items before resuming traffic.【F:tests/mempool/status_probe.rs†L94-L163】
* **Mixed severities.** The regression confirms that multiple alerts can fire simultaneously (for
  example, identity saturation plus transaction warning). Treat them independently—clear the critical
  queue first, then review any remaining warnings to keep the backlog healthy.【F:tests/mempool/status_probe.rs†L130-L163】
* **Alert names and payloads.** The probe encodes Alertmanager-style payloads with `alertname`,
  `queue`, `severity`, and `summary` fields. Expect `TransactionsQueueWarning` when the transaction
  queue crosses the warning threshold and `TransactionsQueueSaturated`/`IdentitiesQueueSaturated`
  at full capacity; failing CI runs write the payloads to
  `target/artifacts/mempool-alert-probe/*.json` (or the directory set in
  `MEMPOOL_ALERT_ARTIFACT_DIR`) for debugging.【F:tests/mempool/status_probe.rs†L100-L207】
* **Operator response.** When a critical payload lands in alerting, pause bulk submissions, raise
  `mempool_limit` to drain legitimate traffic, and clear the saturated queues before resuming
  normal load—mirroring the saturation/recovery sequence validated by the probe.【F:tests/mempool/status_probe.rs†L108-L163】

### Backlog probes

* The `chain-cli health` probe now fails when block proposals or transactions exceed the configured
  backlog thresholds. Override the limits with `--max-block-backlog` and
  `--max-transaction-backlog` when exercising incident drills or staging rollouts, and use the
  JSON output to feed automation that drains queues before restarts.【F:rpp/chain-cli/src/lib.rs†L205-L258】【F:rpp/runtime/node.rs†L330-L361】
* Metrics `rpp_runtime_backlog_blocks` and `rpp_runtime_backlog_transactions` surface the queue
  sizes; dashboards under `telemetry/grafana/dashboards/runtime_backlog.json` and the mirrored
  `docs/dashboards/runtime_backlog.json` highlight the five-minute averages with thresholds that
  match the probe defaults.【F:telemetry/grafana/dashboards/runtime_backlog.json†L1-L66】
* Alerting mirrors the probe: `ops/alerts/runtime/backlog.yaml` pages when block backlog averages
  above 16 or transaction backlog above 4,096 for five minutes. Keep the runbook URL in sync with
  this section so on-call engineers land on the right remediation steps.【F:ops/alerts/runtime/backlog.yaml†L1-L24】
* To validate the plumbing end-to-end, induce backlog by slowing block verification (start the
  validator with a low-powered prover or temporarily disable pruning) and by raising the mempool
  floor while replaying a known spam scenario. The probe should flip to `Unhealthy`, the backlog
  panels should turn red, and the runtime backlog alerts should fire until the queues drain.

### Pruning and wallet metadata hygiene

* Pruning cycles now reconcile the in-memory wallet transaction metadata with the queued mempool
  entries, rebuilding missing proof/witness payloads and dropping metadata records that no longer
  correspond to queued hashes. The node emits `rpp.runtime.mempool.metadata.rehydrated` and
  `rpp.runtime.mempool.metadata.orphans` counters for telemetry and logs a
  `mempool_metadata_reconciled` event (warning if orphans are removed) so operators can confirm the
  cleanup ran after a prune.【F:rpp/runtime/node.rs†L735-L762】【F:rpp/runtime/telemetry/metrics.rs†L153-L208】【F:rpp/runtime/node.rs†L634-L654】
* The integration suite exercises this path while pruning across every enabled proof backend,
  ensuring wallet submissions survive the reconciliation and that orphaned metadata is cleared
  before the next block production loop resumes.【F:tests/mempool/pruning_orphans.rs†L1-L82】

## Configuration and tuning controls

Align tuning changes with the [mempool cleanup runbook](./mempool_cleanup.md) and the on-call
expectations documented in the [operator handbook](./operator-guide.md#mempool-incident-response) so
incident response, configuration changes, and dashboard updates share the same source of truth.【F:docs/mempool_cleanup.md†L1-L132】【F:docs/operator-guide.md†L82-L99】

### Key configuration and environment hooks

| Area | Configuration keys | Live override & env vars | Telemetry to watch |
| --- | --- | --- | --- |
| Queue capacity | `mempool_limit` in `node.toml`, `validator.toml`, or `hybrid.toml` controls the per-queue cap enforced by the runtime.【F:config/node.toml†L16-L123】【F:docs/deployment_observability.md†L155-L182】 | `/control/mempool` accepts `{"limit": ...}` payloads; export `RPC_URL` and `RPP_RPC_TOKEN` before invoking the endpoint, or point `RPP_CONFIG` at a profile that bakes in the new limit before restart.【F:docs/mempool_cleanup.md†L17-L125】【F:docs/configuration.md†L13-L48】 | `/status/node` backlog, `/status/mempool` queue depth, and gossip backlog counters while spam subsides.【F:docs/mempool_cleanup.md†L95-L115】 |
| Fee/priority weighting | `[queue_weights].priority` and `.fee` set the inclusion bias and must sum to 1.0; validation rejects negative values.【F:config/node.toml†L120-L122】【F:rpp/runtime/config.rs†L2070-L2139】 | Combine `{"priority_weight": .., "fee_weight": ..}` with the same `/control/mempool` call used for limit tuning; the exported `RPC_URL` and `RPP_RPC_TOKEN` bindings keep incident scripts consistent.【F:docs/mempool_cleanup.md†L17-L125】 | `/status/mempool` exposes the active weights, while witness proof gossip confirms whether high-fee entries are landing after the adjustment.【F:docs/mempool_cleanup.md†L29-L61】【F:tests/mempool/spam_recovery.rs†L96-L122】 |
| RPC & gossip rate limits | `[network.limits.per_ip_token_bucket.*]` (burst/replenish per class) and `network.p2p.gossip_rate_limit_per_sec` clamp request floods and gossip fan-out.【F:config/node.toml†L37-L80】 | Persist changes in the config referenced by `RPP_CONFIG`, then restart; CLI overrides (`--rpc-*`) are available for short-lived adjustments documented in the configuration guide.【F:docs/configuration.md†L13-L33】 | RPC rate-limit dashboards (token bucket depletion) and gossip throughput gauges to ensure limits bite without starving honest peers.【F:docs/deployment_observability.md†L145-L196】 |

### Fee-market tuning and alert expectations

* The `fee_ordering_survives_proof_and_fee_pressure` probe floods the transaction queue with mixed-fee proofs across every enabled backend, then raises `mempool_limit` to admit a high-fee burst. It asserts that witness gossip reports the submitted fees, that the decoded `/status/mempool` ordering matches fee priority, and that queue alerts clear once capacity is expanded. Failing runs persist `fee-pressure.json` alongside the existing ordering artifacts (guarded by `MEMPOOL_ORDERING_ARTIFACT_DIR`) so operators can review weights, alerts, and observed vs. expected ordering.【F:tests/mempool/fee_pressure.rs†L1-L156】
* CI now executes the mempool probes as part of `cargo xtask test-integration`, ensuring fee-market regressions are caught regardless of which proof backends are enabled. Use the same flow in staging—intentionally saturate the queue to trigger transaction alerts, lift the limit or rebalance weights, and confirm `/status/mempool` returns a fee-descending order and cleared alerts before restoring the steady-state configuration.【F:xtask/src/main.rs†L594-L611】

### Example: harden steady state before a spam burst

1. Review the active profile (`RPP_CONFIG` or `--config`) and raise `mempool_limit` if the default
   8,192 entries leave little headroom relative to `max_block_transactions`; restart to apply the new
   baseline.【F:docs/configuration.md†L13-L33】【F:docs/deployment_observability.md†L155-L182】
2. Rebalance `[queue_weights]` (for example 0.6/0.4) when fee pressure should matter less than age,
   and note the expected telemetry changes so dashboards can alert on drift.【F:docs/deployment_observability.md†L178-L182】
3. Confirm RPC token-bucket replenish and burst values align with expected client concurrency; update
   dashboards to flag depletion and throttled responses ahead of real traffic spikes.【F:config/node.toml†L40-L110】【F:docs/deployment_observability.md†L145-L196】
4. Record the steady-state queue depth, max fee, and gossip throughput from `/status/mempool`,
   `/status/node`, and the telemetry CLI—these snapshots become the “before” baseline referenced in
   the cleanup runbook.【F:docs/mempool_cleanup.md†L29-L115】

### Example: live tuning after spam is detected

1. Follow the cleanup runbook to export `RPC_URL`/`RPP_RPC_TOKEN`, confirm `mempool full` rejections,
   and capture queue occupancy to measure the blast radius.【F:docs/mempool_cleanup.md†L17-L43】
2. Issue a `/control/mempool` request that temporarily raises `mempool_limit` and, if needed, shifts
   the priority/fee weights toward rapid backlog draining; track the updated weights via
   `/status/mempool`.【F:docs/mempool_cleanup.md†L63-L107】
3. While the higher limit is in effect, monitor `/status/node`, witness gossip volume, and token
   bucket consumption to ensure legitimate traffic is flowing and rate limits still shield RPC
   endpoints.【F:docs/mempool_cleanup.md†L95-L115】【F:docs/deployment_observability.md†L145-L196】
4. Once the backlog matches pre-incident baselines, apply the steady-state limit and queue weights
   again (via `/control/mempool` or by restoring the committed configuration) and note the change in
   the incident log alongside the operator handbook guidance.【F:docs/mempool_cleanup.md†L108-L125】【F:docs/operator-guide.md†L82-L99】

### Fairness and eviction expectations

* Each mempool queue enforces the same `mempool_limit`, so spam in one class cannot evict another;
  the eviction probe keeps a running count of rejected transactions and votes to confirm the queue
  isolation is working as configured.【F:tests/mempool/spam_recovery.rs†L210-L305】 Use the artifact
  to corroborate alert payloads when adjusting dashboard thresholds.
* Queue weight tuning (`priority` vs. `fee`) still flows through `/status/mempool`, even while
  queues are saturated, so operators can confirm that new fairness rules are active before
  re-opening traffic after a DoS event.【F:tests/mempool/spam_recovery.rs†L70-L88】【F:tests/mempool/spam_recovery.rs†L289-L304】

## Handling Spam and Rate Limiting

When the configured limit is reached the runtime rejects additional submissions with the
`mempool full` error, effectively rate limiting further spam. Monitor for the error string in RPC
responses or client logs to confirm that the limiter is engaged.【F:tests/mempool/spam_recovery.rs†L49-L61】

After the limiter trips, drain any queued gossip events to avoid replaying stale payloads during
post-mortem analysis.【F:tests/mempool/spam_recovery.rs†L66-L72】

## Recovery Procedures

1. Raise the mempool limit temporarily via `/control/mempool` (or the helper on the node handle) to
   open headroom for legitimate traffic.【F:tests/mempool/spam_recovery.rs†L90-L95】
2. Re-submit critical transactions and confirm that new gossip events arrive with the expected hash
   and fee.【F:tests/mempool/spam_recovery.rs†L96-L105】
3. Watch `/status/node` and `/status/mempool` until the backlog stabilises and high-fee entries are
   present again, signalling recovery.【F:tests/mempool/spam_recovery.rs†L110-L123】
4. Once traffic normalises, reduce the limit back to the desired steady-state value and continue
   monitoring the queue weight telemetry if priority/fee weighting was adjusted. The regression probe
   mirrors this flow by clearing alerts after the limit/weight changes and confirming `/status/node`
   matches the per-queue counts reported by `/status/mempool`; expect the same signals before closing
   a production incident.【F:tests/mempool/status_probe.rs†L165-L248】
5. Restart with the recovered configuration to ensure the alert surface stays clear and queue weights
   remain in effect; the probe validates this by asserting empty alerts and matching weights directly
   after restart.【F:tests/mempool/status_probe.rs†L249-L263】

By mirroring the behaviour exercised in the integration test, operators can close spam incidents
quickly: detect the limiter via error telemetry, verify gossip events for accepted resubmissions,
scale the limit long enough to drain pending work, and finally restore normal operating parameters.
