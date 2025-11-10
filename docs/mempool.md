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
