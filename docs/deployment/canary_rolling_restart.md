# Canary rolling restart and deploy simulation

This canary drill exercises a small-world cluster while performing a rolling
restart. It keeps zk proving/verification and wallet tracker operations active
throughout the rollout so we can spot consensus or client regressions before a
release promotion.

## What the job covers
- **Consensus and zk verification:** The simnet consensus load runs Plonky3-based
  proving and verification with tamper checks to ensure VRF/quorum manipulations
  are rejected.
- **Rolling restart churn:** The p2p simulation injects a steady churn rate so
  validators sequentially restart while traffic continues to flow.
- **Wallet operations:** The Electrs tracker integration test indexes a demo
  block, validates proof metadata, and audits VRF outputs during the rollout
  window.
- **Metrics and logs:** The regression harness writes per-scenario summaries and
  process logs under `target/simnet/canary-rolling-*` for later inspection.

## Running the canary pre-release
Use the dedicated CI job to exercise the drill before promoting a release:

```sh
# Triggered automatically on PRs/branches via `.github/workflows/ci.yml`
# Job name: "Canary rolling deploy simulation"
```

To run the same workload locally (for example before cutting a release tag),
execute the scenario via the simnet regression harness:

```sh
# From the repository root
cargo run -p simnet --bin regression -- \
  --artifacts-root target/simnet/canary-rolling-local \
  --scenario tools/simnet/scenarios/canary_rolling_restart.ron
```

If you prefer the preset wrapper, the simnet CLI exposes the profile:

```sh
cargo xtask simnet --profile canary-rolling --artifacts-dir target/simnet/canary-rolling-local
```

## Reviewing results
1. Download the `simnet-canary-rolling` artifact (or inspect your local
   `target/simnet/canary-rolling-*` directory).
2. Open `regression.json`/`regression.html` for the scenario-level status and
   metrics paths.
3. Check `summaries/canary_rolling_consensus.json` for proving/verification
   latency and tamper outcomes, and
   `summaries/canary_rolling_summary.json` for p2p churn impacts.
4. Inspect `logs/wallet-tracker-regression.log` if the wallet tracker test fails
   or tamper failures are reported; the CI job fails on any non-zero exit or
   missing summary.
