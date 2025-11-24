# Uptime soak coverage and alert responses

The uptime drill keeps block production, timetoke accrual, and finality health on
signal by replaying a long-running simnet profile and probing the alert rules
that guard liveness and finality.

## Simnet uptime soak

The `uptime-soak` simnet profile drives a three-hour small-world topology with
steady transaction flow, induced churn, and a mid-run regional partition to
exercise recovery paths while tracking gossip latency and replay guard metrics.
Use the preset when fuzzing locally or from CI:

```bash
cargo xtask simnet --profile uptime-soak --artifacts-dir target/simnet/uptime-soak-local
```

The RON wrapper points at `scenarios/uptime_soak.toml`, pins CPU/RAM guidance,
and writes JSON/CSV summaries under the `summaries/` directory for dashboards or
postmortems.【F:tools/simnet/scenarios/uptime_soak.ron†L1-L18】【F:scenarios/uptime_soak.toml†L1-L83】

## Alert probes

Alert validation now includes uptime and finality-focused probes in addition to
existing consensus and snapshot checks. The synthetic metric stores induce a
sustained pause (height stall plus widening finality gaps) and a clean recovery
run to confirm alerts fire and then clear:

- **Finality lag and height gap** – warning/critical probes assert the thresholds
  in `ConsensusFinalityLag*` and `ConsensusFinalizedHeightGap*` fire once the lag
  exceeds 12/24 slots or the gap grows past 4/8 blocks for the configured
  windows.【F:tools/alerts/validation.py†L680-L726】【F:tools/alerts/validation.py†L1342-L1375】
- **Liveness stall** – triggers `ConsensusLivenessStall` when block height
  remains flat for ten minutes, mirroring the soak’s induced pause and ensuring
  the alert clears when block production resumes.【F:tools/alerts/validation.py†L728-L737】【F:tools/alerts/validation.py†L1137-L1203】
- **Recovery guard** – the recovery fixture keeps lag and height gaps below
  thresholds while heights advance, proving alerts return to green once the
  network catches up.【F:tools/alerts/validation.py†L1205-L1270】【F:tools/alerts/tests/test_alert_validation.py†L15-L61】
- **Timetoke epoch delay** – simulates a delayed timetoke rollover so
  `TimetokeEpochDelayWarning` and `TimetokeEpochDelayCritical` page when epoch
  age exceeds one or one-and-a-half hours, then drop once epochs resume.【F:tools/alerts/validation.py†L740-L766】【F:tools/alerts/validation.py†L1273-L1316】

Run the probes with the existing validation harness (`python -m pytest
tools/alerts/tests`) whenever alert expressions change to preserve coverage.

## Scheduled coverage

`nightly-simnet` now runs the uptime soak weekly (Monday 01:30 UTC) alongside the
standard simnet suites. Artifacts land under `target/simnet/uptime-soak-nightly`
and are uploaded as `simnet-uptime-soak` for dashboards and regression triage.【F:.github/workflows/nightly.yml†L1-L83】【F:.github/workflows/nightly.yml†L101-L145】

## Response expectations

When the soak or production telemetry raises uptime/finality alerts:

1. **Acknowledge paging alerts.** `ConsensusFinalityLagCritical` or
   `ConsensusLivenessStall` should page on-call; warning variants log to the
   dashboard.
2. **Validate block and finality progress.** Check `chain_block_height`,
   `finality_lag_slots`, and `finalized_height_gap` panels. Confirm whether the
   stall coincides with the partition window in the soak or unexpected proposer
   churn in production.
3. **Reinstate liveness.** If heights are flat, restart stalled proposers,
   rebalance peers, and escalate to the network snapshot failover if lag stays
   above the critical thresholds for more than two evaluation windows.
4. **Confirm timetoke accrual.** After recovery, verify timetoke hours and uptime
   scheduler metrics continue to advance to avoid slashing healthy validators.
5. **Record outcomes.** Attach the simnet summaries and relevant Grafana panels
   to the incident ticket; include the alert probe results when adjusting
   thresholds.

## Alert definitions and probe usage

- **Finality and liveness:** Finality gap and liveness stall probes reuse the
  consensus alert rules for lag (`finality_lag_slots`, `finalized_height_gap`)
  and block stalls (`chain_block_height`).【F:tools/alerts/validation.py†L680-L737】
- **Timetoke epoch delay:** `timetoke_epoch_age_seconds` captures how long the
  current timetoke epoch has been active; warning and critical alerts fire at
  one hour and ninety minutes respectively.【F:tools/alerts/validation.py†L740-L766】【F:tools/alerts/validation.py†L1273-L1316】

To run the probes locally and capture artifacts:

```bash
python -m pytest tools/alerts/tests
python tools/alerts/validate_alerts.py --artifacts target/alert-probes
```

CI executes the same sequence in the `alert-probes` workflow job and uploads the
JSON summary as `alert-probes/alert_probe_results.json`. The job fails if any
expected alert is missing, ensuring regressions are caught before
merge.【F:.github/workflows/ci.yml†L393-L425】【F:tools/alerts/validate_alerts.py†L64-L87】
