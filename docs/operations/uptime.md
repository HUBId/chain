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
- **Prover backlog correlation** – models a rising prover queue depth and p95
  latency while finality lag and uptime observation age cross their warning
  thresholds so `FinalityProverBacklogCorrelation` and
  `UptimeProverLatencyCorrelation` trip with the base warnings. Use the probe to
  confirm prover saturation is visible in dashboards before promoting new
  releases.【F:tools/alerts/validation.py†L915-L1006】【F:ops/alerts/uptime/prover.yaml†L1-L33】
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

## Missed slots under prover load

Nightly simnet now injects rapid leader rotation while saturating the prover to
surface slot coverage regressions early. The liveness rules expose a derived
`consensus:missed_slots:5m` series to make the gap between scheduled slots and
produced blocks explicit. When the warning/critical pages trip:

1. Correlate `consensus:missed_slots:5m` with `consensus:block_production_ratio:5m`
   and `finality_lag_slots` to confirm the deficit is widespread rather than tied
   to a single partition.
2. Inspect per-slot proving latency via `rpp.runtime.proof.generation.duration`
   filtered to `proof_kind="consensus"`; sustained p95 > 5s across slots signals
   queue exhaustion.
3. Verify timetoke replay stays healthy (`timetoke_replay_success_total` vs
   `timetoke_replay_failure_total`) so proposer rotation continues to meet reward
   SLOs while load is high.
4. Quarantine the noisiest leaders, drain prover queues, and resume rotation
   once the missed slot counter trends back below two over a 10m window.

### Mempool-ready probes

Lightweight uptime probes now attempt to submit or observe tiny transactions
while consensus is stalled. The synthetic store drops the
`uptime_mempool_probe_success_ratio` to zero during the induced pause so the
`UptimeMempoolProbeFailure` alert fires alongside finality and liveness stall
signals, then restores the ratio to 1.0 when block production resumes to prove
the probe clears on recovery.【F:tools/alerts/validation.py†L120-L184】【F:tools/alerts/validation.py†L1887-L1969】 Use the alert as
a canary for client-facing impact: if it fires in production, pause bulk
submissions, restart or drain stuck validators, and follow the mempool cleanup
playbook before reopening traffic.【F:docs/mempool.md†L7-L74】

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

### Prover backlog correlation

- **When alerts fire.** `FinalityProverBacklogCorrelation` pages when
  `finality_lag_slots` sits above the 12-slot SLA at the same time a prover
  backend’s queue depth exceeds two jobs. `UptimeProverLatencyCorrelation`
  complements it by pairing the uptime observation age warning threshold with
  prover p95 latency above three minutes, confirming reputation accrual delays
  stem from prover saturation.【F:ops/alerts/uptime/prover.yaml†L1-L33】
- **How to read dashboards.** The updated uptime/finality correlation dashboard
  overlays finality lag with prover queue depth and plots uptime observation age
  against prover p95 latency. Use those panels to confirm whether lag or uptime
  stalls move in lockstep with prover backlogs before restarting validators or
  draining traffic.【F:docs/dashboards/uptime_finality_correlation.json†L1-L129】
- **Triage steps.** Inspect prover pool utilization, widen prover capacity
  limits, or pause new workload until the queue depth falls below two jobs and
  p95 latency returns under three minutes. Once finality lag and uptime
  observation age normalize, close out correlated alerts and re-enable pending
  deploys.【F:tools/alerts/validation.py†L915-L1006】【F:ops/alerts/uptime/prover.yaml†L1-L33】

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

### Planning maintenance windows

- **Overlay maintenance on finality.** Use the “Finality & Maintenance Windows”
  panel in `uptime_finality_correlation.json` to overlay
  `finality_lag_slots` with `rpp_node_pruning_window_events_total` and
  `rpp_node_snapshot_validator_scan_events_total`. Spikes on the start/end
  series mark pruning or snapshot validation windows so responders can confirm
  any finality drift lines up with scheduled work.【F:docs/dashboards/uptime_finality_correlation.json†L121-L173】
- **Watch uptime accrual during work.** The “Uptime Impact of Maintenance”
  panel pairs `uptime_observation_age_seconds` with the same maintenance event
  counters and `rpp_node_uptime_cycle_total{outcome="success"}` to prove
  crediting continues while pruning or snapshot checks run. Growing observation
  age without matching start/end events indicates telemetry or exporter
  regressions rather than planned downtime.【F:docs/dashboards/uptime_finality_correlation.json†L174-L206】
- **Schedule around scan cadence.** Snapshot validation emits
  `rpp.node.snapshot_validator.scan_events_total` at every scan start/end while
  the pruning service emits `rpp.node.pruning.window_events_total` per cycle.
  Use the event rates to pick windows that keep finality lag below the SLA
  budgets above; clusters running hourly scans should avoid overlapping them
  with manual pruning to preserve uptime accrual continuity.【F:rpp/node/src/telemetry/snapshots.rs†L9-L58】【F:rpp/node/src/telemetry/pruning.rs†L9-L83】

### Suppressing uptime/timetoke alerts during maintenance

- **Configure the window in node config.** Declare planned work in the
  `maintenance.windows` stanza with RFC 3339 `starts_at`/`ends_at` timestamps, a
  human-readable `name`, and whether the window should suppress `uptime` and
  `timetoke` alert scopes. Nodes poll this schedule every 30 seconds by
  default, so you can ship a staged config before the window begins.【F:rpp/runtime/config.rs†L2069-L2152】
- **Observe suppression explicitly.** The tracker emits
  `rpp.node.maintenance.window_active{scope="uptime"|"timetoke"}` while a window
  is live and records start/end transitions via
  `rpp.node.maintenance.window_events_total{phase="start|end"}`. Correlate these
  gauges with `maintenance:window_active` in Prometheus to confirm the alerts
  are muted only during the scheduled window.【F:rpp/node/src/telemetry/maintenance.rs†L1-L61】【F:telemetry/prometheus/runtime-rules.yaml†L1-L26】
- **Automatic resumption.** When the window expires the tracker logs that
  suppression lifted and decrements the active gauge, allowing uptime and
  timetoke alerts to fire again once the metrics cross their thresholds.
  Validation fixtures assert the alerts stay silent during the window and resume
  once the window ends while conditions persist.【F:rpp/node/src/services/maintenance.rs†L1-L86】【F:tools/alerts/validation.py†L2113-L2207】

### Reporting cadence

- **CI gates:** The `alert-probes` job in CI runs the probes and fails the build
  when SLA alerts regress, uploading artifacts for triage.【F:.github/workflows/ci.yml†L419-L458】
- **Nightly soak:** The weekly `nightly-simnet` run repeats the probes and logs
  SLA breaches alongside uptime soak artifacts, keeping trend data available for
  the ops review.【F:.github/workflows/nightly.yml†L1-L87】

### Release gate and exception handling

- **Release enforcement:** The release workflow now installs the alert probe
  dependencies, runs the uptime/timetoke validation suite, and uploads the JSON
  artifacts under `alert-probes` so release approvers can audit which alerts
  fired. A failed probe halts the release unless a workflow_dispatch override
  records both an approver and rationale via the `uptime_probe_exception_*`
  inputs, which are echoed in the logs for sign-off traceability.【F:.github/workflows/release.yml†L18-L32】【F:.github/workflows/release.yml†L103-L157】
- **CI parity:** The same pytest + `tools/alerts/validate_alerts.py` sequence
  runs in CI’s `alert-probes` job, keeping the release gate green by detecting
  regressions before tags are cut and ensuring artifact formats stay consistent
  between CI and release uploads.【F:.github/workflows/ci.yml†L419-L458】【F:.github/workflows/release.yml†L118-L151】

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
