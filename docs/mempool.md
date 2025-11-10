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
* `/status/node` exposes the aggregate pending transaction count, allowing dashboards to track the
  backlog as spam ebbs and flows.【F:tests/mempool/spam_recovery.rs†L41-L47】【F:tests/mempool/spam_recovery.rs†L110-L118】
* Subscribe to the internal `WitnessProofs` gossip channel to confirm that successful submissions
  emit events containing the transaction hash and fee, which is useful when correlating accepted
  transactions with rate limit tuning.【F:tests/mempool/spam_recovery.rs†L31-L40】【F:tests/mempool/spam_recovery.rs†L96-L105】
* The `/status/mempool` probe in the integration suite explicitly saturates the queues, verifies that
  warning- and critical-level alerts fire for transactions and identities, and ensures gossip stays
  drained while the probe operates.【F:tests/mempool/status_probe.rs†L77-L163】 Use the same thresholds
  (80% warning, 100% critical by default) when wiring dashboards so that operator alerts align with
  the regression harness.【F:tests/mempool/status_probe.rs†L38-L74】

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

## Configuration and tuning controls

Align tuning changes with the [mempool cleanup runbook](./mempool_cleanup.md) and the on-call
expectations documented in the [operator handbook](./operator-guide.md#mempool-incident-response) so
incident response, configuration changes, and dashboard updates share the same source of truth.【F:docs/mempool_cleanup.md†L1-L132】【F:docs/operator-guide.md†L82-L99】

### Key configuration and environment hooks

| Area | Configuration keys | Live override & env vars | Telemetry to watch |
| --- | --- | --- | --- |
| Queue capacity | `mempool_limit` in `node.toml`, `validator.toml`, or `hybrid.toml` controls the per-queue cap enforced by the runtime.【F:config/node.toml†L16-L123】【F:docs/deployment_observability.md†L155-L182】 | `/control/mempool` accepts `{"limit": ...}` payloads; export `RPC_URL` and `RPP_RPC_TOKEN` before invoking the endpoint, or point `RPP_CONFIG` at a profile that bakes in the new limit before restart.【F:docs/mempool_cleanup.md†L17-L125】【F:docs/configuration.md†L13-L48】 | `/status/node` backlog, `/status/mempool` queue depth, and gossip backlog counters while spam subsides.【F:docs/mempool_cleanup.md†L95-L115】 |
| Fee/priority weighting | `[queue_weights].priority` and `.fee` set the inclusion bias and must sum to 1.0; validation rejects negative values.【F:config/node.toml†L120-L122】【F:rpp/runtime/config.rs†L2070-L2139】 | Combine `{"priority_weight": .., "fee_weight": ..}` with the same `/control/mempool` call used for limit tuning; the exported `RPC_URL` and `RPP_RPC_TOKEN` bindings keep incident scripts consistent.【F:docs/mempool_cleanup.md†L17-L125】 | `/status/mempool` exposes the active weights, while witness proof gossip confirms whether high-fee entries are landing after the adjustment.【F:docs/mempool_cleanup.md†L29-L61】【F:tests/mempool/spam_recovery.rs†L96-L122】 |
| RPC & gossip rate limits | `[network.limits.per_ip_token_bucket]` (burst/replenish) and `network.p2p.gossip_rate_limit_per_sec` clamp request floods and gossip fan-out.【F:config/node.toml†L37-L110】 | Persist changes in the config referenced by `RPP_CONFIG`, then restart; CLI overrides (`--rpc-*`) are available for short-lived adjustments documented in the configuration guide.【F:docs/configuration.md†L13-L33】 | RPC rate-limit dashboards (token bucket depletion) and gossip throughput gauges to ensure limits bite without starving honest peers.【F:docs/deployment_observability.md†L145-L196】 |

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
   monitoring the queue weight telemetry if priority/fee weighting was adjusted.

By mirroring the behaviour exercised in the integration test, operators can close spam incidents
quickly: detect the limiter via error telemetry, verify gossip events for accepted resubmissions,
scale the limit long enough to drain pending work, and finally restore normal operating parameters.
