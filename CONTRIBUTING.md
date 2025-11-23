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
* [Release doc review checklist](RELEASE.md#documentation-review-checklist)
* [RPP vendor refresh procedure](docs/operations/rpp_vendor_update.md)

## [Testing]

After submitting a PR, we'll run all the tests and verify your code meets our submission guidelines. To mirror the branch-protection status checks and catch issues before opening a PR, run the following commands locally:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    ./scripts/test.sh --backend default --unit --integration
    ./scripts/test.sh --backend stwo --unit --integration
    ./scripts/test.sh --backend rpp-stark --unit --integration
    cargo test --test storage_snapshot
    cargo xtask test-observability
    cargo xtask snapshot-verifier
    cargo xtask test-worm-export
    cargo run -p simnet -- --scenario tools/simnet/scenarios/gossip_backpressure.ron
    cargo build --bin rpp-node
    scripts/run_node_mode.sh
    scripts/run_wallet_mode.sh
    scripts/run_hybrid_mode.sh

These steps correspond to the required GitHub checks (`fmt`, `clippy`, `tests-default`, `tests-stwo`, `tests-rpp-stark`, `snapshot-cli`, `observability-snapshot`, `snapshot-verifier`, `worm-export-smoke`, `simnet-admission`, `runtime-smoke`, `Nightly Simulation Freshness`). The test harness applies `RUSTFLAGS=-D warnings`, selects the correct feature flags, and switches to the pinned nightly toolchain automatically when the STWO backend is involved, so local iterations match CI results.【F:.github/workflows/release.yml†L82-L103】【F:scripts/test.sh†L4-L210】【F:tests/storage_snapshot.rs†L1-L73】【F:tests/observability/snapshot_timetoke_metrics.rs†L1-L219】【F:.github/workflows/ci.yml†L360-L397】【F:tools/simnet/scenarios/gossip_backpressure.ron†L1-L16】

Running `cargo doc --no-deps` is still encouraged before landing user-facing API changes to catch documentation regressions early.

The storage hashing and zk-backend combinations covered by CI are summarized in
[`docs/development/testing_matrix.md`](docs/development/testing_matrix.md) so
contributors can quickly map feature flags to the job IDs that exercise them.

### Documentation checks

Pull requests that modify documentation automatically run the **Docs** workflow
to ensure the mdBook snapshot renders and that local file/anchor links resolve.
Reproduce the check locally with:

```
cargo install mdbook --locked --version 0.4.40
cargo install lychee --locked --version 0.15.1
scripts/ci/check_docs.sh
```

The helper script builds a temporary mdBook from `docs/` and the top-level
README/CONTRIBUTING/MIGRATION files, then uses `lychee` to verify that relative
links and fragments point at real files and headings. Fix failures by aligning
relative paths (e.g., `../.github/workflows/ci.yml` from within `docs/`), adding
explicit anchors with `{#my-anchor}` when a fragment targets a section title, or
removing stale links to deleted files before rerunning the command.

### Feature matrix and failure triage

Branch-protection suites (`unit-suites`, `integration-workflows`, `observability-metrics`, `simnet-smoke`) now execute under four feature sets so contributors can surface regressions that only appear once the prover, GUI, or advanced wallet knobs are compiled in.【F:.github/workflows/ci.yml†L635-L940】 Use the table below to reproduce the same combinations locally for any `cargo xtask` command:

| Feature set | Description | Local command |
| --- | --- | --- |
| `default` | Mock prover, no optional wallet flags. | `cargo xtask <command>` |
| `prover_stwo_backend` | Production runtime build with STWO backend. | `XTASK_NO_DEFAULT_FEATURES=1 XTASK_FEATURES="prod,prover-stwo" cargo xtask <command>` |
| `wallet_gui` | Desktop wallet UI compiled via `wallet_gui`. | `XTASK_FEATURES="wallet_gui" cargo xtask <command>` |
| `wallet_advanced` | Wallet security bundle (`wallet_zsi,wallet_hw,wallet_multisig_hooks,wallet_rpc_mtls`). | `XTASK_FEATURES="wallet_zsi,wallet_hw,wallet_multisig_hooks,wallet_rpc_mtls" cargo xtask <command>` |

Substitute `<command>` with `test-unit`, `test-integration`, `test-observability`, or `test-simnet` to mirror the CI jobs. The workflow attaches sanitized log bundles named `unit-suites-<variant>`, `integration-workflows-<variant>`, etc., by running `scripts/ci/collect_test_artifacts.sh` on the `logs/` tree, so failure triage never exposes secrets while still providing the full stdout/stderr and audit reports for each feature set.【F:.github/workflows/ci.yml†L635-L940】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】 Download the matching artifact from the Actions run whenever one of the matrix jobs fails; its content aligns with the commands above, allowing you to replay the run locally with the same feature flags before pushing a fix.

**Maintainer note.** Whenever a workflow file is renamed or a new CI job is
introduced, confirm that branch protection still enforces the `fmt`, `clippy`,
`tests-default`, `tests-stwo`, `tests-rpp-stark`, `snapshot-cli`,
`observability-snapshot`, `snapshot-verifier`, `worm-export-smoke`,
`simnet-admission`, `runtime-smoke`, and `Nightly Simulation Freshness` checks
on `<PRIMARY_BRANCH_OR_COMMIT>`. Navigate to `Settings → Branches → Branch
protection rules` in the GitHub UI or run the
`gh api repos/:owner/:repo/branches/<PRIMARY_BRANCH_OR_COMMIT>/protection`
query to verify the status-check list before merging follow-up changes.

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

**Release owners:** when preparing a tagged release, follow the
[`RELEASE.md`](RELEASE.md#documentation-review-checklist) documentation review
checklist. Capture sign-off on the operator guide, security runbooks, and RPC
policy updates in your release tracking issue or PR description so the audit
trail stays visible to reviewers.

### RPC schema changes

Breaking RPC changes must document the expected removal version and a concrete
deprecation window. When deprecating a field, add an entry to
`tests/rpc/deprecated_fields.toml` with the target removal version and expiry
date. The `deprecated_fields_require_version_bump_or_expiry` test fails CI if a
field disappears before the allowed version or if an expiry date passes without
action. Update the release notes alongside the allowlist entry so downstream
clients can schedule migrations.

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
