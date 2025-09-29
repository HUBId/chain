# Release Notes

## Nightly Dependency & Update Process

The project currently depends on the `nightly-2024-06-20` Rust toolchain. Releases must confirm that this nightly pin still compiles, formats, and lints cleanly before the artefact is tagged. The migration plan targets Rust `1.79` as the next stable baseline; consult `MIGRATION.md` for the readiness checklist.

### Risks

- Nightly regressions can break the workspace with little notice. Mitigate by caching toolchains and mirroring CI jobs onto the prospective stable channel.
- Nightly-only features may be deprecated or altered, requiring rapid code changes. Track the upstream release notes and stabilisation proposals.
- Contributors running default stable toolchains may encounter build failures until the stable switch is complete.

### Update Process

1. Run the full validation suite (`scripts/build.sh`, `scripts/test.sh`, `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`).
2. Execute the stable validation path with `RUSTUP_TOOLCHAIN=1.79.0` to compare results.
3. Update documentation (README, CONTRIBUTING, MIGRATION) if toolchain requirements change.
4. Announce the outcome in the release communication channel and update the tracking issues.

### Manual Checks per Release

- [ ] Confirm `rust-toolchain.toml` points to the intended release channel.
- [ ] Verify CI pipelines completed against both nightly and stable targets.
- [ ] Review benchmarking dashboards for regressions versus the previous release.
- [ ] Ensure new backend feature flags are documented and gated appropriately.
- [ ] Validate release artefacts (binaries, Docker images, manifests) were built with the pinned toolchain.
