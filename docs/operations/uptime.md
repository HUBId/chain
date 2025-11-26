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
- **Missed slots and blocks** – synthetic stores now model proposers skipping
  slots (lag/gap growth followed by recovery) and a flat block height section to
  prove `ConsensusFinalityLag*` and `ConsensusLivenessStall` alerts fire and
  clear when production resumes.【F:tools/alerts/validation.py†L1342-L1485】【F:tools/alerts/tests/test_alert_validation.py†L15-L61】
- **Timetoke epoch delay** – simulates a delayed timetoke rollover so
  `TimetokeEpochDelayWarning` and `TimetokeEpochDelayCritical` page when epoch
  age exceeds one or one-and-a-half hours, then drop once epochs resume.【F:tools/alerts/validation.py†L740-L766】【F:tools/alerts/validation.py†L1273-L1316】
- **Restart/finality correlation** – drives a synthetic restart (via
  `process_start_time_seconds`) that coincides with widening finality lag and
  finalized height gaps to assert the new `ConsensusRestartFinalityCorrelation`
  rule fires alongside the standard warning alerts.【F:tools/alerts/validation.py†L882-L955】【F:ops/alerts/consensus/finality.yaml†L35-L52】
- **RPC availability** – issues steady `/health/live` calls where the success
  ratio drops below 99% for more than five minutes (and below 95% for ten),
  proving `RpcAvailabilityDegraded*` alerts trip while consensus liveness still
  advances via `consensus:block_height_delta:5m`. Recovery fixtures return the
  ratio above 99% to confirm alerts clear independently of liveness probes.【F:tools/alerts/validation.py†L151-L223】【F:tools/alerts/validation.py†L1988-L2042】【F:ops/alerts/rpc/availability.yaml†L1-L32】
- **Join and removal churn** – `uptime-join` keeps `uptime_participation_ratio`,
  `uptime_observation_age_seconds`, and `timetoke_accrual_hours_total`
  progressing through node joins, while `uptime-departure` forces those
  metrics below the SLA to prove `UptimeParticipationDrop*`,
  `UptimeObservationGap*`, and `TimetokeAccrualStall*` alerts fire on sustained
  drops.【F:tools/alerts/validation.py†L852-L1064】【F:tools/alerts/validation.py†L1318-L1428】【F:tools/alerts/tests/test_alert_validation.py†L19-L88】

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
6. **Handle churn-induced drops.** When `UptimeParticipationDrop*` or
   `UptimeObservationGap*` fire after adding or removing validators, restart the
   uptime scheduler on the affected nodes, revalidate RPC and gossip reachability,
   and pause further removals until `timetoke_accrual_hours_total` recovers above
   the warning rate.【F:tools/alerts/validation.py†L1066-L1164】【F:tools/alerts/validation.py†L1318-L1428】

### Consensus liveness and RPC availability

- **Consensus liveness (`ConsensusLivenessStall`).** Fires when
  `consensus:block_height_delta:5m` stays flat for ten minutes. Validate gossip
  connectivity, proposer rotation, and P2P health; if blocks still fail to
  advance, drain traffic to healthy validators until the delta turns positive
  again.【F:ops/alerts/consensus/liveness.yaml†L1-L22】【F:tools/alerts/validation.py†L64-L128】【F:docs/dashboards/uptime_finality_correlation.json†L69-L93】
- **RPC availability (`RpcAvailabilityDegraded*`).** Trips when the RPC success
  ratio (`rpc:availability_ratio:5m`) falls below 99%/95% for five/ten minutes.
  Check ingress or load balancer health, validate `/health/ready` responses, and
  consider redirecting client traffic while consensus continues to make
  progress. Use the uptime/finality dashboard panel to confirm the API outage is
  isolated from consensus liveness and finality graphs.【F:ops/alerts/rpc/availability.yaml†L1-L32】【F:tools/alerts/validation.py†L128-L223】【F:docs/dashboards/uptime_finality_correlation.json†L1-L93】

## Alert definitions and probe usage

- **Finality and liveness:** Finality gap and liveness stall probes reuse the
  consensus alert rules for lag (`finality_lag_slots`, `finalized_height_gap`)
  and block stalls (`chain_block_height`).【F:tools/alerts/validation.py†L680-L737】
- **Timetoke epoch delay:** `timetoke_epoch_age_seconds` captures how long the
  current timetoke epoch has been active; warning and critical alerts fire at
  one hour and ninety minutes respectively.【F:tools/alerts/validation.py†L740-L766】【F:tools/alerts/validation.py†L1273-L1316】

## Clock drift thresholds and mitigation

- **Backward skew guardrail:** Uptime proofs must never claim an observation
  window that ends after the node clock. Both STWO and Plonky3 provers reject
  witnesses where `node_clock < window_end`, and the verifier records the
  rejection so it can be surfaced as an alert.【F:tests/uptime_clock_skew.rs†L25-L99】
- **Forward skew tolerance:** The proofs allow forward skew but operations
  should treat any clock more than five minutes ahead of NTP as a release
  blocker. Alerts should watch for spikes in uptime rejection metrics alongside
  host-level NTP drift gauges.

When drift triggers an alert:

1. Compare the host clock against your stratum-1 reference and resync with
   `chronyc makestep` or an equivalent NTP step once the offset is confirmed.
2. Restart only the uptime scheduler (or the validator service if scheduler
   restart is unavailable) to pick up the corrected clock without disrupting
   consensus traffic.
3. Confirm the verifier rejection counters stop climbing and that subsequent
   uptime proofs are accepted before closing the incident.【F:tests/uptime_clock_skew.rs†L25-L99】

## SLA targets and reporting

### Targets

- **Missed proposer slots:** Keep `finality_lag_slots` below twelve slots under
  normal conditions; hitting twenty-four slots for two minutes is treated as an
  SLA breach and pages the on-call.【F:ops/alerts/consensus/finality.yaml†L5-L34】【F:ops/alerts/consensus/finality.yaml†L17-L34】
- **Finalized height gap:** Maintain a gap under four blocks; a sustained gap of
  eight blocks for two minutes is the critical SLA ceiling.【F:ops/alerts/consensus/finality.yaml†L35-L66】
- **Block production:** `chain_block_height` must advance within ten minutes to
  avoid a liveness breach; the stall probe models this SLA in the alert
  validation harness.【F:tools/alerts/validation.py†L780-L808】
- **Slot budget adherence:** Keep the five-minute block production ratio above
  0.9; dips below 0.75 for ten minutes page on-call via the
  `ConsensusBlockProductionLag*` alerts. The ratio divides block height
  increases by scheduled slots (`consensus_block_schedule_slots_total`) to track
  missed production against the configured block interval.【F:telemetry/prometheus/runtime-rules.yaml†L5-L78】【F:ops/alerts/consensus/liveness.yaml†L1-L52】【F:tools/alerts/validation.py†L865-L1007】

### Measurement

- **Prometheus expressions:** The SLA budgets are encoded directly in the alert
  rules via `max_over_time(finality_lag_slots[5m]) > {12,24}` and
  `max_over_time(finalized_height_gap[5m]) > {4,8}`. The CI alert probes reuse
  the same thresholds to replay missed-slot and stalled-finality scenarios.
- **Synthetic probes:** `tools/alerts/validation.py` centralizes the SLA
  thresholds so both the Prometheus expressions and the probe fixtures share the
  same numbers, preventing drift between alerting and validation.【F:tools/alerts/validation.py†L16-L43】【F:tools/alerts/tests/test_alert_validation.py†L1-L86】

### Environment-aware slicing and promotion gates

- **Environment labels everywhere:** Uptime and RPC alerting rules now aggregate
  and forward the `environment` label so pages are grouped by staging, canary,
  or production. The Grafana correlation dashboard inherits the same label and
  exposes an environment template to slice restarts, finality lag, block rate,
  and RPC availability by deployment ring.【F:telemetry/prometheus/runtime-rules.yaml†L1-L75】【F:ops/alerts/consensus/liveness.yaml†L1-L45】【F:ops/alerts/rpc/availability.yaml†L1-L32】【F:docs/dashboards/uptime_finality_correlation.json†L1-L120】
- **Pre-promotion probes:** A dedicated `staging-slo-probes` CI job reuses the
  staging soak orchestration to validate snapshot health, Timetoke SLOs, and
  admission reconciliation against staging-like endpoints before a production
  promotion proceeds. The job fails when staging SLOs regress and uploads the
  timestamped summary for incident follow-up.【F:.github/workflows/ci.yml†L434-L516】【F:xtask/src/main.rs†L3058-L3361】

### Reporting cadence

- **CI gates:** The `alert-probes` job in CI runs the probes and fails the build
  when SLA alerts regress, uploading artifacts for triage.【F:.github/workflows/ci.yml†L419-L458】
- **Nightly soak:** The weekly `nightly-simnet` run repeats the probes and logs
  SLA breaches alongside uptime soak artifacts, keeping trend data available for
  the ops review.【F:.github/workflows/nightly.yml†L1-L87】

To run the probes locally and capture artifacts:

```bash
python -m pytest tools/alerts/tests
python tools/alerts/validate_alerts.py --artifacts target/alert-probes
```

CI executes the same sequence in the `alert-probes` workflow job and uploads the
JSON summary as `alert-probes/alert_probe_results.json` plus an `exit_code.txt`
capturing probe failures. The nightly drill mirrors the CI job and preserves
artifacts even when probes fail, making it easier to debug missed-slot or block
stall regressions.【F:.github/workflows/ci.yml†L393-L425】【F:.github/workflows/nightly.yml†L1-L87】【F:tools/alerts/validate_alerts.py†L16-L87】【F:tools/alerts/validate_alerts.py†L89-L131】

### Historical baselines and buffers

Uptime and timetoke alerts now key off rolling 30-day baselines with explicit
buffers instead of fixed thresholds. Recording rules track the median
participation ratio (`uptime:participation_ratio:30d_p50`), 90th percentile
observation gap and epoch age, and median timetoke accrual rate. Alert
expressions clamp against those baselines with warning/critical buffers (2.3%
and 5.3% participation drops, +600s/+1500s observation gaps, +1800s/+3600s
epoch age, and a 0.0003 hours/s timetoke rate guard) while preserving the SLA
floors.【F:telemetry/prometheus/runtime-rules.yaml†L58-L196】【F:ops/alerts/uptime/reputation.yaml†L1-L151】

The new `uptime-baseline-guard` CI and nightly jobs run
`tools/alerts/check_baseline_metrics.py` against a Prometheus text dump to keep
the buffered thresholds honest. They default to the committed staging snapshot
(`tools/alerts/fixtures/uptime_timetoke.prom`) but accept fresh exports via the
`--metrics-log` flag so operators can compare production captures before
promotions.【F:tools/alerts/check_baseline_metrics.py†L1-L149】【F:.github/workflows/ci.yml†L459-L489】【F:.github/workflows/nightly.yml†L66-L99】

Update cadence: refresh `tools/alerts/fixtures/uptime_timetoke.prom` every
Monday after the nightly soak by exporting the latest staging metrics with
timestamps (e.g. `curl -sf $PROM_URL/api/v1/export -d 'match[]={__name__=~"uptime.*|timetoke.*"}' > metrics.prom`). Then run
`python tools/alerts/check_baseline_metrics.py --metrics-log metrics.prom` to
confirm the buffers still hold before committing the refreshed snapshot so the
CI and nightly guards track recent behavior.【F:tools/alerts/fixtures/uptime_timetoke.prom†L1-L16】
