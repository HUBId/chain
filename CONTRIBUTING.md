# Welcome contributors

We are eager for contributions and happy you found yourself here.
Please read through this document to familiarize yourself with our
guidelines for contributing to ztate (the chain repository).

## Table of Contents

* [Quick Links](#Quick Links)
* [Testing](#testing)
* [How to submit changes](#How to submit changes)
* [Where can I ask for help?](#Where can I ask for help)

## [Quick Links]

* [Setting up docker](README.docker.md)
* [Issue tracker](https://github.com/ava-labs/chain/issues)

## [Testing]

After submitting a PR, we'll run all the tests and verify your code meets our submission guidelines. To mirror the branch-protection status checks and catch issues before opening a PR, run the following commands locally:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    ./scripts/test.sh --backend default --unit --integration
    ./scripts/test.sh --backend stwo --unit --integration
    ./scripts/test.sh --backend rpp-stark --unit --integration
    cargo test --test storage_snapshot
    cargo xtask test-observability
    cargo run -p simnet -- --scenario tools/simnet/scenarios/gossip_backpressure.ron
    cargo build --bin rpp-node
    scripts/run_node_mode.sh
    scripts/run_wallet_mode.sh
    scripts/run_hybrid_mode.sh

These steps correspond to the required GitHub checks (`fmt`, `clippy`, `tests-default`, `tests-stwo`, `tests-rpp-stark`, `snapshot-cli`, `observability-snapshot`, `simnet-admission`, `runtime-smoke`, `Nightly Simulation Freshness`). The test harness applies `RUSTFLAGS=-D warnings`, selects the correct feature flags, and switches to the pinned nightly toolchain automatically when the STWO backend is involved, so local iterations match CI results.【F:.github/workflows/release.yml†L82-L103】【F:scripts/test.sh†L4-L210】【F:tests/storage_snapshot.rs†L1-L73】【F:tests/observability/snapshot_timetoke_metrics.rs†L1-L219】【F:tools/simnet/scenarios/gossip_backpressure.ron†L1-L16】

Running `cargo doc --no-deps` is still encouraged before landing user-facing API changes to catch documentation regressions early.

**Maintainer note.** Whenever a workflow file is renamed or a new CI job is
introduced, confirm that branch protection still enforces the `fmt`, `clippy`,
`tests-default`, `tests-stwo`, `tests-rpp-stark`, `snapshot-cli`,
`observability-snapshot`, `simnet-admission`, `runtime-smoke`, and `Nightly
Simulation Freshness` checks on `<PRIMARY_BRANCH_OR_COMMIT>`. Navigate to
`Settings → Branches → Branch protection rules` in the GitHub UI or run the `gh
api repos/:owner/:repo/branches/<PRIMARY_BRANCH_OR_COMMIT>/protection` query to
verify the status-check list before merging follow-up changes.

### Nightly simulation freshness gate

The `Nightly Simulation Freshness` check fails when the most recent `nightly.yml`
run on the default branch concluded with a non-success status or is older than
24 hours. When the gate is red:

1. Re-run the nightly workflow from the Actions tab (choose `nightly.yml` and
   click **Run workflow**) or via CLI:

   ```bash
   gh workflow run nightly.yml
   ```

2. Inspect the logs for the failed nightly run to determine the failing job.
   Use the `gh run view <run-id> --log` command or download the artifact bundle
   for the simulation/SLO summary.
3. Fix the underlying regression, or if the failure was environmental,
   re-run the affected nightly job and ensure the follow-up run completes
   successfully. Only merge once the check is green again so branch protection
   can verify the dependency on healthy nightly results.

Property-based tests in the workspace respect the `PROPTEST_CASES` environment
variable so CI can run a smaller, deterministic sample. When a failure occurs,
re-run the suite locally with the provided seed to reproduce it:

```
PROPTEST_CASES=256 PROPTEST_SEED=<failing-seed> cargo test -p rpp-chain -- tests_prop
```

Increasing `PROPTEST_CASES` is recommended before landing changes that touch
those code paths so the new invariants see additional coverage.

## [How to submit changes]

To create a PR, fork the ztate repository on GitHub and open the PR from your fork. We typically prioritize reviews in the middle of our next work day,
so you should expect a response during the week within 24 hours.

## [How to report a bug]

Please use the [issue tracker](https://github.com/ava-labs/chain/issues) for reporting issues.

## [First time fixes for contributors]

The [issue tracker](https://github.com/ava-labs/chain/issues) typically has some issues tagged for first-time contributors. If not,
please reach out. We hope you work on an easy task before tackling a harder one.

## [How to request an enhancement]

Just like bugs, please use the [issue tracker](https://github.com/ava-labs/chain/issues) for requesting enhancements. Please tag the issue with the "enhancement" tag.

## [Style Guide / Coding Conventions]

We generally follow the same rules that `cargo fmt` and `cargo clippy` will report as warnings, with a few notable exceptions as documented in the associated Cargo.toml file.

By default, we prohibit bare `unwrap` calls and index dereferencing, as there are usually better ways to write this code. In the case where you can't, please use `expect` with a message explaining why it would be a bug, which we currently allow. For more information on our motivation, please read this great article on unwrap: [Using unwrap() in Rust is Okay](https://blog.burntsushi.net/unwrap) by [Andrew Gallant](https://blog.burntsushi.net).

## [Where can I ask for help]?

Please reach out on X (formerly twitter) @rkuris for help or questions!

## Thank you

We'd like to extend a pre-emptive "thank you" for reading through this and submitting your first contribution!
