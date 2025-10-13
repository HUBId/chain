# Release Notes

## Stable Toolchain Workflow

The project is standardised on the Rust `1.79.0` toolchain. Each release must confirm that this stable pin continues to compile, format, and lint cleanly before the artefact is tagged. Toolchain health is summarised in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md), and migration criteria are tracked in `MIGRATION.md`.

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
