# Migration Guide

## Switching from Nightly to Stable

1. Run the full validation suite on the existing nightly toolchain, including formatting (`cargo fmt --check`), linting (`cargo clippy --all-targets --all-features -- -D warnings`), and the project's test scripts, to capture any regressions ahead of the migration.
2. Update dependencies or code as needed to resolve nightly-only features identified by the validation passes.
3. Once the codebase is stable-friendly, edit `rust-toolchain.toml` to point to the desired stable release channel. If the project no longer requires a pinned toolchain, remove the file entirely so that contributors fall back to their default Rust installation.
4. Communicate the change to the team, including any newly required components or workflows, and confirm CI is running against the stable channel before merging the migration.

## Promoting STWO to Stable

Once the STWO prover feature is ready for general availability:

1. Update the stable CI job to pass `--features prover-stwo` to its build, test, and lint steps so that the default release flow exercises the new prover implementation.
2. Remove or disable the nightly `prover-stwo` job if it is no longer needed for feature-gating or benchmarking, or keep it scheduled only for extended performance checks.
3. Clean up any documentation that still references the mock prover for stable releases to avoid confusion for downstream consumers.
