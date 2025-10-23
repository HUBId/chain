# Testing Strategy

This repository layers multiple feedback loops to cover protocol correctness and
runtime regressions:

- **Unit and component tests** live alongside the crates they exercise. They run
  on every PR and focus on pure logic (cryptography, storage primitives,
  protocol state machines) with tight execution budgets.
- **Integration tests** under `tests/` boot self-contained nodes and clusters to
  validate end-to-end flows such as gossip propagation and wallet pipelines.
- **Regression scenarios** (added in this change) orchestrate Tokio-driven
  harnesses that exercise the full validator stack with realistic timings. They
  are designed to run both locally and in CI and serve as the final safety net
  before a release.

## Regression suite

The regression suite lives under `tests/regression/` and currently ships four
scenarios:

1. **Cluster bootstrap** – spins up a three-node validator cluster and verifies
   that a full mesh forms and quorum advances beyond the initial baseline.
2. **Wallet transaction** – submits a transfer through the pipeline orchestrator
   and asserts that the sender nonce, sender balance and recipient balance match
   the workflow preview once rewards are distributed.
3. **Proof generation** – waits for a finalised block and ensures the node
   persisted the proof bundle (transaction proofs, state proof, pruning proof,
   recursive proof) for the latest height.
4. **Snapshot recovery** – restarts a validator from on-disk state and confirms
   that consensus height and block availability survive the restart.

Each scenario records structured JSON metrics, baseline snapshots and
human-readable log lines into the directory referenced by the
`RPP_REGRESSION_ARTIFACT_DIR` environment variable. The harness uses
`tests/regression/mod.rs` to write metrics under `metrics/`, per-scenario logs in
`logs/` and snapshot material in `snapshots/`.

### Running locally

```bash
scripts/run_regression.sh
```

By default the script writes artefacts to `ci-artifacts/regression/` relative to
the repository root. Override the target directory by exporting
`RPP_REGRESSION_ARTIFACT_DIR` before invoking the script. The suite takes roughly
20 minutes on a 4 vCPU developer machine due to validator bootstrap time and the
proof generation path.

### CI integration

The workflow defined in `.github/workflows/regression.yml` runs the script on
pull requests touching relevant code as well as on pushes to `main`. Artefacts
are uploaded as `regression-suite` for later inspection, and the workflow
publishes the expected runtime and produced artefacts to the job summary. This
ensures that the regression scenarios are exercised consistently across
contributors and release candidates.

## Fast feedback loops

The regression suite complements, but does not replace, the existing fast
checks:

- `cargo test` (without the regression target) should remain part of the
  developer inner loop.
- `cargo fmt --check` and `cargo clippy --all-targets --all-features` keep the
  codebase consistent and linted.
- The UI workspace maintains its own Playwright-based smoke checks in
  `.github/workflows/validator-ui.yml`.

Combining these layers provides a balance between fast iteration and realistic
system validation.
