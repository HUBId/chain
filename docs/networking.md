# Networking Simulation Playbooks

The networking harness exposes curated simulation scenarios that exercise the
libp2p stack under adverse conditions. This document highlights the
partitioned-flood scenario added to the simnet catalogue and explains how to
interpret the derived metrics.

## Partitioned Flood Scenario

> **Runbook:** [Network partition response](./operations/network_partition.md)

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

## Gossip Tuning Checklist

Production incidents tied to gossip saturation generally fall into three
categories: bandwidth ceilings, connection floods, and replay windows that are
too narrow for the active mesh. Operators can tune all three via the standard
configuration files and verify the impact through Prometheus metrics.

### 1. Throttle gossip bandwidth explicitly

1. Edit the profile that maps to the deployment tier (for example,
   `config/node.toml`, `config/hybrid.toml`, or `config/validator.toml`) and
   raise or lower `network.p2p.gossip_rate_limit_per_sec` under the `[network.p2p]`
   table. The value caps accepted gossip publications from a single peer per
   second; defaults range from 128 (standalone node) to 256 (validator).
   【F:config/node.toml†L99-L115】【F:config/hybrid.toml†L120-L139】【F:config/validator.toml†L105-L124】
2. Restart the runtime so the new rate limit propagates to the libp2p rate
   limiter (`RateLimiter::new(Duration::from_secs(1), gossip_rate_limit_per_sec)`).
   【F:rpp/p2p/src/swarm.rs†L830-L847】
3. Confirm the change by scraping `pipeline_gossip_events_total` and computing a
   per-second rate. A sustained rate near the limit indicates that upstream
   peers need to be throttled or reshaped.

### 2. Bound connection fan-out

1. Apply per-host HTTP connection shaping to protect the RPC ingress path by
   adjusting `network.limits.per_ip_token_bucket` (burst and replenish values) in
   the node configuration. This governs how many simultaneous requests a single
   IP may issue before throttling kicks in.【F:config/node.toml†L35-L52】
2. For the gossip layer, restrict which peers may connect by seeding
   `network.p2p.allowlist` with known peer IDs (and tiers) and enforcing
   blocklist entries for untrusted senders. Admission control rejects peers that
   fall outside these lists, ensuring the active mesh stays within the planned
   fan-out envelope.【F:rpp/runtime/config.rs†L801-L848】【F:rpp/p2p/src/peerstore.rs†L503-L585】
3. Monitor `rpp_gossip_peer_score` alongside `pipeline_gossip_events_total`; a
   sudden increase in low-scoring peers or spikes in accepted gossip rates
   signals that connection limits should be tightened further.

### 3. Enlarge replay protection windows before upgrades

1. Increase `network.p2p.replay_window_size` when rolling out large payloads or
   longer partitions so the replay protector retains more digests. The guard
   enforces a minimum of 128 entries and rejects zero-capacity windows during
   configuration validation.【F:config/node.toml†L107-L115】【F:rpp/runtime/config.rs†L808-L856】
2. Restart the node to rebuild the `ReplayProtector` with the new capacity.
   `ReplayProtector::with_capacity(replay_window_size)` preloads persisted
   digests and starts rejecting duplicates once the window fills.【F:rpp/p2p/src/swarm.rs†L1007-L1010】【F:rpp/p2p/src/security.rs†L7-L68】
3. Watch the replay telemetry surfaced through admission metrics to ensure the
   enlarged window no longer drops legitimate replays during catch-up.

## Alerting and Dashboards

The following snippets capture common Prometheus and Grafana artefacts that tie
directly into the gossip metrics exported by the runtime.

### Replay guard alerts

The replay protector exposes counters and gauges for duplicate drops and window
utilisation on every validator. Operators should wire the following thresholds
into their telemetry stack to catch regressions before the mesh ejects fresh
payloads:

* **Duplicate drops.** Alert when
  `increase(network_replay_guard_drops_total[5m]) > 50` for five minutes and
  escalate to critical once the five-minute increase exceeds 200. The warning
  signal indicates sustained duplicate chatter, while the critical threshold
  confirms the guard is actively discarding traffic.【F:ops/alerts/networking/replay_guard.yaml†L5-L34】
* **Window saturation.** Raise a warning when
  `max_over_time(network_replay_guard_window_fill_ratio[5m]) > 0.85` for ten
  minutes and page at 0.95 for five minutes. These gauges report how full the
  replay cache is and directly map to the risk of evicting legitimate digests
  during churn.【F:ops/alerts/networking/replay_guard.yaml†L35-L64】

Import the sample rules under
`ops/alerts/networking/replay_guard.yaml` into Alertmanager/Prometheus and pair
them with the Grafana panel template in
`ops/alerts/networking/replay_guard_grafana.json` for a turnkey drill-down
dashboard.【F:ops/alerts/networking/replay_guard.yaml†L1-L64】【F:ops/alerts/networking/replay_guard_grafana.json†L1-L63】

```yaml
# prometheus/rules/gossip.yml
groups:
  - name: gossip-bandwidth
    rules:
      - alert: GossipRateSaturating
        expr: rate(pipeline_gossip_events_total{outcome="success"}[5m])
              > bool scalar(0.85 * 256)
        for: 10m
        labels:
          severity: page
        annotations:
          summary: "Gossip throughput at {{ $labels.instance }} is above 85% of the configured limit"
          runbook: docs/networking.md#gossip-tuning-checklist
          limit: "Update 256 to the active network.p2p.gossip_rate_limit_per_sec before deploying"
```

Pair the alert with a Grafana stat panel that highlights both inbound bandwidth
and per-topic mesh pressure:

```json
{
  "type": "stat",
  "title": "Gossip bandwidth (5m rate)",
  "targets": [
    {
      "expr": "sum by (direction) (rate(rpp_gossip_bytes[5m]))",
      "legendFormat": "{{direction}}"
    }
  ],
  "transformations": [
    {
      "id": "organize",
      "options": {
        "indexByName": "direction"
      }
    }
  ]
}
```

* `pipeline_gossip_events_total` is incremented inside the runtime orchestrator
  whenever a gossip publish succeeds or fails, making it the canonical source
  for message rates.【F:rpp/runtime/orchestration.rs†L358-L370】【F:rpp/runtime/orchestration.rs†L482-L486】
* `rpp_gossip_bytes` exposes inbound/outbound byte totals per topic straight
  from the libp2p registry, supporting both dashboards and alerting on mesh
  saturation.【F:rpp/p2p/src/swarm.rs†L536-L603】

## Nightly Coverage

The nightly workflow includes an optional job named `simnet-partitioned-flood`
that executes the scenario, runs the analyzer, and uploads a compressed artifact
containing the summary directory. The job is marked as non-blocking but still
runs on every schedule, providing continuous telemetry on partition recovery and
backpressure heuristics.

Replay protection coverage is exercised via the `networking` integration suite.
The `replay_alert_probe_saturates_window_triggers_alerts` test loads the sample
alert definitions, simulates replay saturation, and verifies that both the drop
rate and window-fill alerts fire. The nightly networking workflow executes this
probe to keep the Alertmanager snippets in sync with the documented thresholds.【F:tests/networking/replay_alert_probe.rs†L1-L153】【F:.github/workflows/nightly.yml†L120-L144】
