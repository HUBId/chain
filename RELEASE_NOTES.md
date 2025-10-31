# Release Notes

For the secure release process, see the updated [RELEASES.md](RELEASES.md)
runbook and [SECURITY.md](SECURITY.md) policy that describe the CI gates,
signing requirements, and advisory flow enforced by the latest pipelines.

## Stable Toolchain Workflow

The project is standardised on the Rust `1.79.0` toolchain. Each release must confirm that this stable pin continues to compile, format, and lint cleanly before the artefact is tagged. Toolchain health is summarised in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md), and migration criteria are tracked in `MIGRATION.md`.

## Prover Backend Wiring

- `rpp/node`, `rpp/wallet`, and `rpp/consensus` now enable the `prover/prover_stwo_backend` crate whenever the `prover-stwo` feature is active, replacing their previous interface-only relationship. The `prover-mock` feature continues to keep the backend disabled.

## Documentation

- Added [Validator Quickstart](docs/validator_quickstart.md) and
  [Validator Troubleshooting](docs/validator_troubleshooting.md) guides covering
  installation, configuration with `config/node.toml`, rollout feature gates,
  telemetry options, and recovery procedures for VRF mismatches and missing
  snapshots.
- Updated the Poseidon VRF notes to highlight the `/status/node` telemetry
  payload and the `target_validator_count` / `rollout.telemetry.*` knobs in
  `config/node.toml`, giving operators concrete endpoints and toggles for the
  new metrics.【F:docs/poseidon_vrf.md†L55-L104】【F:config/node.toml†L8-L76】
- Documented den vollständigen Pipeline-Lifecycle inklusive Orchestrator-Hooks,
  Telemetrie-Metriken und dem Smoke-Test `tests/pipeline/end_to_end.rs`, damit
  Releases die Produktionstauglichkeit der Wallet→Firewood-Kette hervorheben.
  Die zugehörigen Dashboards (`docs/observability/pipeline.md`) und das
  Lifecycle-Dossier (`docs/lifecycle/pipeline.md`) sind als Referenz verlinkt
  und verweisen auf die Blueprint-Abdeckung.【F:docs/lifecycle/pipeline.md†L1-L86】【F:tests/pipeline/end_to_end.rs†L1-L122】【F:docs/observability/pipeline.md†L1-L74】【F:docs/blueprint_coverage.md†L73-L121】

### Risks

- Stable patch releases can change lint or formatting behaviour. Cache toolchains in CI to avoid mid-release drift and re-validate when a new 1.79.x patch lands.
- Dependencies may add nightly-only features in minor updates. Track upstream release notes and stabilisation proposals to plan the upgrade path.
- Contributors using older stable compilers may encounter build failures. Communicate the minimum required version prominently in README and onboarding docs.

### Update Process

1. Run the full validation suite (`scripts/build.sh`, `scripts/test.sh --all --integration`, `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`).
2. Execute the suite with `RUSTUP_TOOLCHAIN=1.79.0` explicitly to ensure CI and local behaviour match.
3. Capture any deviations in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md) and update documentation (README, CONTRIBUTING, MIGRATION) if toolchain requirements change.
4. Announce the outcome in the release communication channel and update the tracking issues.

### Manual Checks per Release

- [ ] Confirm `rust-toolchain.toml` pins the intended stable release.
- [ ] Verify CI pipelines completed against the stable toolchain matrix.
- [ ] Review benchmarking dashboards for regressions versus the previous release.
- [ ] Ensure new backend feature flags are documented and gated appropriately.
- [ ] Validate release artefacts (binaries, Docker images, manifests) were built with the pinned toolchain.
