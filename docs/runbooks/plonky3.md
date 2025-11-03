# Plonky3 Prover Runbook

This runbook documents the operational procedures for the production Plonky3
prover/verifier stack introduced in Phase 2. Use it alongside the
[`rpp-node` operator guide](../rpp_node_operator_guide.md) and the
[consensus performance report](../performance/consensus_proofs.md) when preparing
or troubleshooting deployments. The Phase‑2 production checklist lives in the
[Plonky3 Production Validation Checklist](../testing/plonky3_experimental_testplan.md),
which enumerates the artefacts and commands auditors expect before a rollout.【F:docs/testing/plonky3_experimental_testplan.md†L1-L121】

## 1. Validation before rollout

1. **Build artefacts**
   - Compile the release binary with `--features prod,backend-plonky3` (see
     `scripts/build_release.sh`).
   - Run `scripts/verify_release_features.sh` to ensure that mock features are
     absent and that `backend-plonky3` is present in the metadata.
2. **Key material**
   - Seed proving/verifying key caches by executing
     `rpp-node validator proofs preload --backend plonky3` or by letting the
     first production block generation populate `backend_health.plonky3.*`.
   - Verify that the cache directory contains all circuit families listed in the
     blueprint (transaction, state, pruning, uptime, consensus).
3. **Integration checks**
   - Run `scripts/test.sh --backend plonky3 --unit --integration`.
   - Execute the consensus stress harness:
     `cargo run -p simnet -- --scenario tools/simnet/scenarios/consensus_quorum_stress.ron`.
     Review the generated summary with `scripts/analyze_simnet.py` and confirm
     that the p95 latencies stay below the documented acceptance criteria and
     that all tamper attempts are rejected.

## 2. Monitoring & dashboards

* **Metrics**
  - `rpp.runtime.proof.generation.latency_ms{backend="plonky3",proof="<kind>"}`
    (p50/p95/avg counters exported via Prometheus).
  - `rpp.runtime.proof.verification.latency_ms{backend="plonky3"}` for verifier
    latency.
  - `rpp.runtime.proof.generation.failures_total{backend="plonky3"}` and
    `rpp.runtime.proof.verification.failures_total{backend="plonky3"}` for
    failure counts.
  - `backend_health.plonky3` fields exposed via `/status/node` for cache size,
    last key rotation timestamp, and active circuits.
* **Dashboards**
  - Import `docs/dashboards/consensus_proof_validation.json` into Grafana.
    Panels track prove/verify latency percentiles, proof sizes, cache hit rates,
    and tamper rejection counters.
  - Embed the dashboard in the production overview so acceptance evidence is
    available to stakeholders.
* **Alerts**
  - Trigger warning alerts when prove p95 exceeds 5.5 s for more than two
    consecutive minutes.
  - Fire critical alerts when any tampered proof is accepted or when the prover
    failure counter increases without a corresponding `backend_health.plonky3`
    recovery event.

## 3. Incident response

1. **Unexpected latency spike**
   - Inspect Grafana for correlation with cache evictions or witness volume.
   - Check system metrics (GPU utilisation if enabled, disk throughput for
     cache directories).
   - If caches were evicted, reseed using the preload command and monitor the
     next five blocks.
2. **Tamper acceptance**
   - Immediately quarantine the offending validator witness data and trigger an
     emergency key rotation via `rpp-node validator vrf rotate`.
   - Review `scripts/analyze_simnet.py` thresholds; if tamper rejection logic
     regressed, roll back to the last known good release.
3. **Prover failures**
   - Collect logs filtered by `target="plonky3"` and attach them to the
     incident ticket.
   - Verify that vendor assets (circuits, parameters) are present and match the
     checksums recorded in the vendor log.
   - Restart the prover service after clearing incomplete cache entries.

## 4. Post-incident checklist

- Update the [performance report](../performance/consensus_proofs.md) if new
  benchmarks were taken during the investigation.
- File a postmortem that includes the Grafana panel export, relevant log
  excerpts, and remediation steps.
- Review alert thresholds and automation scripts to prevent recurrence.

## 5. References

- [`docs/blueprint_coverage.md`](../blueprint_coverage.md)
- [`docs/testing/plonky3_experimental_testplan.md`](../testing/plonky3_experimental_testplan.md)
- [`docs/roadmap_implementation_plan.md`](../roadmap_implementation_plan.md)
- [`docs/test_validation_strategy.md`](../test_validation_strategy.md)
