# Network Partition Response Runbook

This runbook guides on-call operators through detecting, mitigating, and recovering from network partitions or flooding incidents that sever gossip connectivity.

## Detection signals

Use both metrics and logs to confirm that the node is partitioned rather than simply slow:

* **`rpp_gossip_decisions` counters.** A spike in `decision="rejected"` labelled with `reason="tier_insufficient"` or `reason="duplicate"` indicates that peers are being cut off or retrying aggressively because their view of the mesh diverged.【F:rpp/p2p/src/metrics.rs†L59-L126】
* **`pipeline_gossip_events_total` rates.** Sustained drops below the configured gossip bandwidth limit highlight that publications are no longer flowing. Pair the rate with the configured limit from the [gossip tuning checklist](../networking.md#gossip-tuning-checklist).【F:docs/networking.md†L59-L115】
* **`recovery_resume_events` samples.** When a partition heals, the recovery export increments the counter and reports latency buckets. Zero samples while alerts fire usually means the mesh has not reconnected yet.【F:rpp/sim/src/metrics/exporters.rs†L63-L84】
* **`telemetry.gossip` logs.** `gossip_publish_rejected` warnings capture the peer, topic, and rejection reason, helping you correlate metrics spikes with the underlying peers.【F:rpp/p2p/src/gossip/mod.rs†L1-L41】

Escalate when Prometheus shows a five-minute rate of rejected gossip decisions above the steady-state baseline or when the flood/partition simulations begin failing their nightly thresholds.

## Immediate mitigation

1. **Isolate unhealthy peers.** Blocklist peers that are flapping or stuck on an outdated mesh while you investigate. Either call the authenticated RPC directly or apply a pre-approved quarantine snapshot with the CLI:

   ```sh
   # Blocklist a peer immediately via the RPC API.
   curl -X POST -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
        -H 'Content-Type: application/json' \
        ${RPP_RPC_URL}/p2p/admission/policies \
        -d '{
              "actor": "ops.oncall",
              "reason": "isolate partitioned peer",
              "blocklist": ["12D3KooWPartitionedPeer"]
            }'

   # Apply the emergency quarantine snapshot that blocklists the peer set.
   rpp-node validator admission restore \
     --backup emergency-quarantine \
     --actor ops.oncall \
     --reason "quarantine partitioned peer" \
     --approval operations:ops.oncall \
     --approval security:sec.oncall
   ```

   Both surfaces persist the change atomically, emit an audited entry, and update the peerstore snapshot so the blocklist survives restarts.【F:rpp/rpc/src/routes/p2p.rs†L126-L209】【F:rpp/node/src/main.rs†L1188-L1315】

2. **Throttle the mesh.** Reduce the gossip rate limit or tighten per-IP token buckets if the issue is caused by a flood. Adjust the `[network.p2p]` parameters in the active configuration bundle, then restart the node to apply the change.【F:docs/networking.md†L59-L104】【F:rpp/p2p/src/swarm.rs†L830-L847】

3. **Confirm admission controls.** Query `GET /p2p/admission/policies` or run `rpp-node validator admission verify --audit-limit 0` to verify that critical peers remain allowlisted and that only the unhealthy peers are blocked.【F:docs/network/admission.md†L35-L69】【F:rpp/node/src/main.rs†L1306-L1397】

4. **Communicate.** Update the incident timeline with the affected peer IDs, metrics snapshots, and any configuration overrides you applied.

## Recovery validation

1. **Watch the metrics return to baseline.** `pipeline_gossip_events_total` should climb back toward the configured limit once the mesh heals, and the rejected branch of `rpp_gossip_decisions` should flatten.【F:docs/networking.md†L59-L115】【F:rpp/p2p/src/metrics.rs†L59-L126】
2. **Check resume latency exports.** The recovery summary should show non-zero `resume_events` and decreasing `max_resume_ms` as peers resubscribe.【F:rpp/sim/src/metrics/exporters.rs†L63-L84】
3. **Inspect logs for recovery markers.** `telemetry.gossip` should flip from `gossip_publish_rejected` warnings to `gossip_publish_allowed` debug lines, confirming that the mesh accepted the resumed flow.【F:rpp/p2p/src/gossip/mod.rs†L1-L29】
4. **Audit admission state.** Once traffic stabilises, remove temporary blocklist entries via the same RPC/CLI so the mesh returns to its steady-state topology.【F:docs/network/admission.md†L35-L69】【F:rpp/node/src/main.rs†L1306-L1397】

Document the incident outcome, the duration of the partition, and any configuration deltas left in place.

## Rehearsal guidance

Exercise this runbook ahead of time with the partition simulations:

* **Partitioned flood (`partitioned_flood`).** Run `cargo run --locked --package simnet -- --scenario tools/simnet/scenarios/partitioned_flood.ron --artifacts-dir target/simnet/partitioned-flood` followed by `python3 scripts/analyze_simnet.py target/simnet/partitioned-flood/summaries/partitioned_flood.json` to replay the transient-partition plus flood scenario used by Nightly.【F:docs/networking.md†L9-L28】
* **Snapshot partition (`snapshot_partition`).** Use `tools/simnet/scenarios/snapshot_partition.ron` to practise state-sync recovery while the mesh is partitioned; the generated summaries include the same `resume_events` and latency metrics exposed in production chaos drills.【F:tools/simnet/scenarios/snapshot_partition.ron†L1-L13】【F:docs/testing/simulations.md†L59-L140】

Capture the resume latency charts and rejected gossip counts during rehearsals so you can compare them against production incidents.
