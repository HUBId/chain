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

These steps correspond to the required GitHub checks (`fmt`, `clippy`, `tests-default`, `tests-stwo`, `tests-rpp-stark`). The test harness applies `RUSTFLAGS=-D warnings`, selects the correct feature flags, and switches to the pinned nightly toolchain automatically when the STWO backend is involved, so local iterations match CI results.【F:.github/workflows/release.yml†L82-L103】【F:scripts/test.sh†L4-L210】

Running `cargo doc --no-deps` is still encouraged before landing user-facing API changes to catch documentation regressions early.

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
