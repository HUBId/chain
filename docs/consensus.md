# Consensus finality operations

The consensus pipeline exports finality lag and finalized height gap gauges so
operators can confirm whether validators are finalizing new blocks in time. This
page summarises the alerting thresholds, validation drills, and remediation
playbooks that accompany those signals.

## Finality lag metrics, alerts, and dashboards {#finality-lag}

### Metric primers

* `finality_lag_slots` measures how many slots the last finalized block lags the
  accepted tip. Sustained growth means validators are not completing rounds fast
  enough.
* `finalized_height_gap` measures the block height difference between the
  finalized head and the accepted head. Height gaps often grow more slowly than
  slot lags but are easier to cross-check with explorer views.

### Alert expectations

#### `finality_lag_slots`

* **Warning (`ConsensusFinalityLagWarning`):** fires when the maximum observed
  lag over five minutes exceeds twelve slots.
* **Critical (`ConsensusFinalityLagCritical`):** fires when the lag breaches
  twenty-four slots for two minutes.

Both alerts read from `ops/alerts/consensus/finality.yaml` and rely on the
`max_over_time` aggregator to smooth short spikes.【F:ops/alerts/consensus/finality.yaml†L1-L36】
Investigate recent proposer rotations, ensure the active validator set is
healthy, and confirm that witnesses continue to sign new rounds.

#### `finalized_height_gap`

* **Warning (`ConsensusFinalizedHeightGapWarning`):** triggers when the finalized
  height trails the accepted head by more than four blocks for five minutes.
* **Critical (`ConsensusFinalizedHeightGapCritical`):** pages when the gap stays
  above eight blocks for two minutes.

The alerts are defined in the same rule file and surface sustained gaps that
would otherwise stall pipeline consumers.【F:ops/alerts/consensus/finality.yaml†L37-L66】
When they fire, correlate the panel with `finality_lag_slots` and prepare to
execute the failover checklist.

### Example dashboards

Embed the metrics in two Grafana rows so operators can jump from alerts to a
shared view:

* **Finality lag slots panel:** graph `max_over_time(finality_lag_slots[5m])`
  with warning/critical thresholds at 12 and 24 slots. Add a stat panel showing
  the current max lag and a table breaking down lag by validator ID to spot a
  single slow proposer.
* **Finalized height gap panel:** graph `max_over_time(finalized_height_gap[5m])`
  with alert thresholds at 4 and 8. Pair with a bar chart of finalized vs.
  accepted heights per region or AZ to expose regional stalls.
* **Corollary panels:** include `validator_peer_connectivity` and CPU load for
  consensus nodes to correlate infrastructure health with lag spikes. Link
  drilldowns to the incident log for faster post-mortems.

### Typical remediation steps

1. Confirm the alert source. Open the Grafana finality dashboard and verify the
   lag or gap persisted for at least two evaluation windows.
2. Check proposer health. Ensure the active validator set is connected, has
   sufficient peers, and is not throttled by CPU or disk I/O. Restart isolated
   nodes that stopped signing rounds.
3. Compare against network upgrades or backend switches. If lag followed a
   backend change, follow the [Zero-data-loss backend switch procedure](./zk_backends.md#zero-data-loss-backend-switch-procedure)
   to revert or complete the rollout safely. If forks or verifier stalls are
   involved, hand off to the [incident response runbook](./operations/incidents.md)
   for quorum restart, failover, and pruning safeguards.
4. Execute the [network snapshot failover runbook](runbooks/network_snapshot_failover.md)
   to shift traffic away from degraded validators and restore proposer rotation.
5. Document the timeline, Grafana snapshots, and mitigations in the incident log
   and attach them to the alert ticket.

## Missed slots and stalled block production

Consensus alerts also guard against missed proposer slots and prolonged blocks
stalling the chain:

* **Missed slots:** the same `finality_lag_slots` and `finalized_height_gap`
  alerts act as an early warning when proposers fail to produce or finalize
  blocks. Warning thresholds trip after five minutes above 12 slots or four
  blocks, with critical pages at 24 slots and eight blocks for two minutes.【F:ops/alerts/consensus/finality.yaml†L1-L66】
* **Missed blocks:** `ConsensusLivenessStall` fires when
  `chain_block_height` stays flat over a ten-minute window, indicating stalled
  block production even if finality appears healthy.【F:tools/alerts/validation.py†L780-L808】

When either alert fires:

1. **Confirm proposer rotation.** Check the `finality_lag_slots` and
   `chain_block_height` panels to verify whether the gap is still widening or
   whether blocks have resumed.
2. **Recover stuck proposers.** Bounce validators that stopped producing,
   rebalance peers, and check for throttled resources (CPU, disk) before the
   critical window elapses.
3. **Validate clearance.** Ensure the lag drops below the warning thresholds
   and block height resumes increasing; the missed-slot recovery drill in the
   alert probes records that alerts clear once metrics return to baseline.【F:tools/alerts/validation.py†L1424-L1485】【F:tools/alerts/tests/test_alert_validation.py†L15-L61】

## Validation drills

`cargo test --test finality_alert_probe` replays the alert thresholds and
verifies that the warning/critical levels escalate correctly for both metrics.
Run the probe after modifying alert rules to prove that simulated delayed
finality raises the expected signals.【F:tests/consensus/finality_alert_probe.rs†L1-L89】

If the probe fails locally or in CI, it writes `probe.log` and `metrics.prom`
to `FINALITY_ALERT_ARTIFACT_DIR` (defaults to
`target/artifacts/finality-alert-probe`). CI exposes sanitized copies under
`artifacts/observability/<feature-matrix>/finality-alert-probe` in the workflow
artifacts so on-call reviewers can quickly retrieve them.【F:tests/consensus/finality_alert_probe.rs†L25-L201】【F:.github/workflows/ci.yml†L100-L121】

To debug a failure:

1. Read `probe.log` to confirm the expressions, parsed thresholds, and the
   trigger/quiet sample sets.
2. Inspect `metrics.prom` with `promtool check metrics metrics.prom` or import
   it into a temporary Prometheus to replay the two scenarios.
3. Compare the recorded samples against the alert definitions to understand why
   an escalation fired or was suppressed, then adjust the expressions or
   thresholds accordingly.

## Clock drift fuzzing and safe budgets

Nightly fuzzing now exercises epoch transitions under skewed clocks and slow
peers through two complementary checks:

* The integration test in `tests/consensus_epoch_drift.rs` starts four
  validators with staggered `block_time_ms`/`round_timeout_ms` values, throttles
  gossip on one peer, and asserts that two epoch transitions complete without
  fork-choice divergence or excessive round-latency spread (>1.2s).【F:tests/consensus_epoch_drift.rs†L1-L165】
* The simnet `epoch-drift` profile drives a 30-node small-world mesh with a
  cross-region partition and churn, recording per-peer latency and consensus
  summaries for the nightly soak pipeline.【F:tools/simnet/scenarios/consensus_epoch_drift.ron†L1-L20】【F:scenarios/epoch_drift.toml†L1-L70】

The combined drills have held finality steady with ~110ms of per-validator slot
skew and latency spread under 1.2s. Operators should treat ~1s of additional
round latency and a one-block height spread as the safe drift budget; crossing
those limits warrants deeper inspection before tightening alert thresholds.

## RPP-STARK reorg drills and observability

Nightly simnet runs now include an RPP-STARK-specific reorg scenario that
builds competing chains, rejects conflicting votes, validates the proof bundles
on the winning branch, and proves the chain can recover with fresh finality
after the fork.【F:tools/simnet/scenarios/consensus_reorg_rpp_stark.ron†L1-L31】【F:tests/reorg_rpp_stark.rs†L1-L263】 Operators should
expect the following telemetry and logs when replaying or debugging the drill:

* **Verifier counters:** `rpp.runtime.verifier.accepted_total{backend="rpp-stark"}`
  should increment as soon as the canonical bundle is revalidated. The test
  asserts a non-zero accepted count and records the rejection of a tampered
  proof when a byte is flipped in the state proof.
* **Slashing events:** conflicting prevotes/precommits emit
  `ConsensusFault` entries in the validator slashing log. The scenario checks
  for at least two new events, confirming double-sign protection stays wired.
* **Fork-choice confirmation:** the latest block remains pinned to the
  pre-fork hash while conflicting votes are rejected. After submitting a new
  transaction, the recovered tip must advance and finality markers reappear in
  `consensus_status` responses, demonstrating healthy progress past the fork.

When these signals deviate (e.g., verifier accept counters remain zero or the
tip height stalls), capture `rpp-node` logs with `rpp.consensus` and
`rpp.proofs` targets enabled, export the slashing ledger via `node_handle
slashing_events`, and rerun the simnet scenario with `--keep-alive` to inspect
the intermediate proof bundles before engaging the incident runbook.

