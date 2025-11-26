# Slashing incident investigation

Operators can replay the slashing guardrails locally or in CI to verify that equivocations and double-signs are penalised for both STWO and RPP-STARK validators. The workflow also documents how to triage alerts and metrics when a validator is suspected of misbehaviour.

## Reproduce the guardrail locally

1. Run the dedicated simnet scenario against the production feature set:
   ```bash
   cargo run --locked --package simnet -- \
     --scenario tools/simnet/scenarios/consensus_slashing_backends.ron \
     --artifacts-dir target/simnet/consensus-slashing-backends
   ```
2. Repeat the same scenario with the RPP-STARK verifier enabled:
   ```bash
   cargo run --locked --no-default-features --features prod,prover-stwo,backend-rpp-stark --package simnet -- \
     --scenario tools/simnet/scenarios/consensus_slashing_backends.ron \
     --artifacts-dir target/simnet/consensus-slashing-backends-rpp
   ```
3. Inspect `logs/` under the chosen artifacts directory and confirm that each `applied slashing penalty` entry includes `backend=...` as well as `evidence=double_sign`. Alerts should spike once the evidence is recorded and clear after the next commit.
4. Check the metrics snapshots (if telemetry is enabled) for increments in `consensus_slashing_events_total` and backend-tagged verification counters. When absent, scrape the node’s `/metrics` endpoint to confirm the counters advance and then settle.

## Alert-handling checklist

1. **Identify the offender.** Use validator telemetry (`validator/telemetry` RPC) to correlate `slashing_events` with the accused validator and backend.
2. **Verify pipeline health.** Ensure the consensus logs include `backend=<active>` and `evidence=double_sign`; missing backend labels often indicate mismatched prover/verifier features.
3. **Confirm alert recovery.** Once slashing penalties are applied, the subsequent `take_slashing_triggers()` poll should be empty and Alertmanager should return to green. Persistent alerts imply stuck evidence or stalled reward distribution.
4. **Escalate with artifacts.** Attach the simnet artifacts (including `logs/` and any metrics snapshots) alongside the relevant Alertmanager firing/clearing payloads. Mention whether the reproduction used STWO, RPP-STARK, or both.

## Nightly coverage

The `nightly-simnet` workflow runs the guardrail scenario in both the default (STWO) and `backend-rpp-stark` matrices. If an alert fires overnight, download the `simnet-nightly` or `simnet-rpp-stark-nightly` artifacts and follow the steps above to pinpoint the offending backend and validator.
