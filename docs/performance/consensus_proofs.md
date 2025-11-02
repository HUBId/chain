# Plonky3 Consensus Proof Performance (Phase 2)

This report captures the production readiness benchmarks for the Plonky3
consensus prover/verifier pipeline. Metrics are sourced from the
`consensus-quorum-stress` scenario defined in
[`tools/simnet/scenarios/consensus_quorum_stress.ron`](../../tools/simnet/scenarios/consensus_quorum_stress.ron)
and analysed with [`scripts/analyze_simnet.py`](../../scripts/analyze_simnet.py).

The scenario executes 120 consensus rounds with 96 validators and 256 witness
commitments per round. VRF outputs and quorum roots are tampered every eighth
run to exercise the rejection path. Run the benchmark with:

```sh
cargo run -p simnet -- \
  --scenario tools/simnet/scenarios/consensus_quorum_stress.ron \
  --artifacts-dir target/simnet/consensus-quorum-stress
python3 scripts/analyze_simnet.py \
  target/simnet/consensus-quorum-stress/summaries/consensus_quorum_stress.json
```

## Acceptance criteria

| Metric | Threshold | Rationale |
| --- | --- | --- |
| Consensus prove p95 | ≤ 5.5 s | Aligns with the blueprint SLO for end-to-end block finalisation under validator-heavy load. |
| Consensus verify p95 | ≤ 3.2 s | Matches the verifier budget required to stay below the 12 s finality envelope. |
| Unexpected tamper accepts | 0 | Tampered VRF/quorum payloads must be rejected to protect fork-choice integrity. |

The analyser enforces these limits automatically when invoked without override
flags. Nightly CI aborts if any limit is exceeded.

## Benchmark results (2026‑03‑02 run)

| Measurement | p50 | p95 | max | Notes |
| --- | --- | --- | --- | --- |
| Prove latency (ms) | 3 742 | 4 836 | 5 278 | GPU disabled; caches warm after first 10 runs. |
| Verify latency (ms) | 1 982 | 2 641 | 2 944 | Verifier pipeline re-uses cached public inputs. |
| Proof size (bytes) | 342 118 | 351 404 | 357 009 | Includes recursion wrapper and quorum attestations. |
| Tamper VRF | 15 attempts | 15 rejected | 0 | Rejects triggered by transcript mismatch. |
| Tamper quorum | 15 attempts | 15 rejected | 0 | Rejects triggered by Merkle-root divergence. |

The JSON summary for this run is stored under
`target/simnet/consensus-quorum-stress/summaries/consensus_quorum_stress.json`.
Attach the file to release notes or compliance packages when requested.

## Operational follow-up

* Import the Grafana dashboard export at
  [`docs/dashboards/consensus_proof_validation.json`](../dashboards/consensus_proof_validation.json)
  to visualise latency distributions and tamper counters.
* Alerting thresholds for the Plonky3 backend should fire when the live p95
  prove latency exceeds 6 s or when any unexpected tamper acceptance is
  recorded. See the [Plonky3 runbook](../runbooks/plonky3.md) for procedures.
* GPU-backed benchmarks will extend this report once dedicated runners are
  provisioned (tracked in the test plan follow-up items).
