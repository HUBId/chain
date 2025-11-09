# Networking Simulation Playbooks

The networking harness exposes curated simulation scenarios that exercise the
libp2p stack under adverse conditions. This document highlights the
partitioned-flood scenario added to the simnet catalogue and explains how to
interpret the derived metrics.

## Partitioned Flood Scenario

The [`tools/simnet/scenarios/partitioned_flood.ron`](../tools/simnet/scenarios/partitioned_flood.ron)
wrapper executes the [`scenarios/partitioned_flood.toml`](../scenarios/partitioned_flood.toml)
configuration in-process. The topology alternates two regions, introduces a
transient partition, and enables churn to force peer recovery while aggressively
publishing transactions. The flood phase ramps the publish rate to 42 tx/s and
is followed by a cool-down window that allows the mesh to recover.

To reproduce the nightly run locally:

```bash
cargo run --locked --package simnet -- \
  --scenario tools/simnet/scenarios/partitioned_flood.ron \
  --artifacts-dir target/simnet/partitioned-flood
python3 scripts/analyze_simnet.py \
  target/simnet/partitioned-flood/summaries/partitioned_flood.json
```

The analysis script prints propagation, recovery, bandwidth, and backpressure
summaries. It also enforces thresholds that align with the nightly workflow.

## Metrics of Interest

* **Peer recovery** &mdash; `resume_events`, `max_resume_ms`, and `mean_resume_ms`
  surface when the harness detects the partition healing. The analyzer now fails
  runs that report a recovery block without any resume latency samples so we can
  distinguish genuine failovers from inactive code paths.
* **Bandwidth throttling** &mdash; the simnet collector records slow-peer events
  emitted by gossipsub. The aggregated counters (`bandwidth_throttling`) track
  how many unique peers were throttled and how often the queue thresholds were
  hit. Zero throttled peers now causes the analyzer to flag a configuration
  issue.
* **Gossip backpressure** &mdash; `gossip_backpressure` reports the number of slow
  peer events along with queue-full, publish, forward, and timeout failures. The
  analyzer treats a zero queue-full count as a failure to ensure that the flood
  phase stresses backpressure handling.

The raw event stream is written to
`target/simnet/partitioned-flood/summaries/partitioned_flood.json`, while the
CSV export offers a condensed view suitable for dashboards.

## Nightly Coverage

The nightly workflow includes an optional job named `simnet-partitioned-flood`
that executes the scenario, runs the analyzer, and uploads a compressed artifact
containing the summary directory. The job is marked as non-blocking but still
runs on every schedule, providing continuous telemetry on partition recovery and
backpressure heuristics.
