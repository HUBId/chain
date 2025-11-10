# Consensus finality operations

The consensus pipeline exports finality lag and finalized height gap gauges so
operators can confirm whether validators are finalizing new blocks in time. This
page summarises the alerting thresholds, validation drills, and remediation
playbooks that accompany those signals.

## Alert expectations

### `finality_lag_slots`

* **Warning (`ConsensusFinalityLagWarning`):** fires when the maximum observed
  lag over five minutes exceeds twelve slots.
* **Critical (`ConsensusFinalityLagCritical`):** fires when the lag breaches
  twenty-four slots for two minutes.

Both alerts read from `ops/alerts/consensus/finality.yaml` and rely on the
`max_over_time` aggregator to smooth short spikes.【F:ops/alerts/consensus/finality.yaml†L1-L36】
Investigate recent proposer rotations, ensure the active validator set is
healthy, and confirm that witnesses continue to sign new rounds.

### `finalized_height_gap`

* **Warning (`ConsensusFinalizedHeightGapWarning`):** triggers when the finalized
  height trails the accepted head by more than four blocks for five minutes.
* **Critical (`ConsensusFinalizedHeightGapCritical`):** pages when the gap stays
  above eight blocks for two minutes.

The alerts are defined in the same rule file and surface sustained gaps that
would otherwise stall pipeline consumers.【F:ops/alerts/consensus/finality.yaml†L37-L66】
When they fire, correlate the panel with `finality_lag_slots` and prepare to
execute the failover checklist.

## Validation drills

`cargo test --test finality_alert_probe` replays the alert thresholds and
verifies that the warning/critical levels escalate correctly for both metrics.
Run the probe after modifying alert rules to prove that simulated delayed
finality raises the expected signals.【F:tests/consensus/finality_alert_probe.rs†L1-L89】

## Remediation

1. Collect Grafana snapshots for the finality lag and finalized height panels.
2. Follow the [network snapshot failover runbook](runbooks/network_snapshot_failover.md)
   to reroute traffic away from unhealthy validators and recover block
   production.【F:docs/runbooks/network_snapshot_failover.md†L1-L176】
3. Document the remediation in the incident log alongside the alert drill output
   from the validation probe to close the loop with the failover procedures.
