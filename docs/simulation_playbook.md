# Simulation Playbook

## Large cluster multiprocess scenario

The `scenarios/large_cluster.toml` profile exercises a 120 node deployment split across
20 validators and 100 wallet clients. It is configured for the multi-process harness so the
baseline in-process simulator is compared against a process-per-node cluster during the same
run. Latency and jitter parameters are region-aware to emulate cross-continental links and the
traffic program blends Poisson and bursty phases to stress gossip and proof propagation.

Run the scenario locally with:

```shell
cargo run --package rpp-sim -- --scenario scenarios/large_cluster.toml
```

The default `mode = "compare"` first executes the in-process simulation and then launches the
multi-process harness via `rpp/sim/src/multiprocess.rs`. Output summaries are exported to
`target/sim-large/report.json` and `target/sim-large/report.csv`. Pass `--mode inprocess` to only
execute the baseline when iterating locally.

## Metrics captured

The report extends the existing propagation and mesh-change telemetry with additional KPIs:

* **Reputation and tier drift** – per-validator receive counts are used to compute mean and
  standard deviation. Validators are also binned into four tiers (tl1-tl4) to highlight skew.
* **BFT success rate** – each propagated proof is treated as a round with the quorum threshold
  derived from the configured validator count. The report surfaces the total rounds observed and
  the percentage that reached quorum.
* **Proof latency** – p50/p95/p99 and maximum propagation times in milliseconds.
* **Performance KPIs** – aggregate publish/receive throughput, duplicate rate, runtime duration,
  and the mean proof latency when available.

Per-node publish/receive counters are included in the `node_performance` array to enable deeper
post-processing.

## CI coverage and thresholds

The `.github/workflows/sim_large.yml` workflow runs on PRs and pushes that touch the simulator,
scenario, or documentation. It executes the large cluster scenario, validates the resulting
`target/sim-large/report.json` with `scripts/check_sim_large.py`, and uploads the report directory
as a build artifact.

The KPI checker enforces conservative guardrails:

* `bft_success.success_rate` must stay above 50% with at least one observed round.
* `performance.receive_rate_per_sec` must remain above 0.1 events/s.
* `performance.duplicate_rate` must stay below 50%.
* `proof_latency.p99_ms` is capped at 60 seconds when present.
* `reputation_drift.std_dev_receives` must not exceed 1.5× the mean plus a small buffer.

Failures print descriptive error messages so teams can adjust the scenario, investigate regressions,
or update the thresholds when new behaviour is expected.
