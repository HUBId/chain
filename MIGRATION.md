# Migration Guide

## Node Configuration Schema Versioning

Use the following checklist when the `NodeConfig` schema changes:

- [ ] Bump `NODE_CONFIG_VERSION` in `rpp/runtime/config.rs` and update the
      `config_version` field in sample configs (e.g. `config/node.toml`).
- [ ] Document operator-facing changes and migration steps in `docs/` and the
      release notes.
- [ ] Provide an upgrade procedure that includes backing up the previous
      configuration and running validation via `rpp-chain config validate` (or
      the equivalent CLI entry point).
- [ ] Communicate the new version to validators and ensure automation or
      orchestration scripts fail-fast on mismatches.

### Hot-reload evaluation

`NodeConfig` is loaded during start-up and its values are wired into subsystems
such as networking, storage, and consensus before the main runtime begins. The
current runtime does not support re-initialising those components on the fly,
so hot-reloading configuration files would not apply the updated values safely
and could leave the process in an inconsistent state. Operators should restart
the node after editing configuration files to pick up changes.

## Maintaining the Stable Toolchain

Use the following checklist to keep the `1.83.0` workflow healthy:

- [ ] **Toolchain**
  - [ ] Run the full validation suite on the pinned stable compiler (`1.83.0`) whenever a release candidate is cut.
  - [ ] Re-run the suite after upstream `1.83.x` patch releases and capture any deltas in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md).
  - [ ] Update `rust-toolchain.toml` if the minimum supported Rust version changes and communicate the date of enforcement.
- [ ] **Feature flags & crates**
  - [ ] Audit `Cargo.toml` and workspace members for `#![feature(...)]` attributes or nightly-only dependencies before accepting upgrades.
  - [ ] Gate unstable functionality behind cfg flags or replace it with stable equivalents.
  - [ ] Refresh documentation snippets and examples to reflect stable-compatible syntax.
- [ ] **CI configuration**
  - [ ] Keep CI jobs (build, test, lint, docs) on the stable toolchain matrix and ensure caches are refreshed when the compiler is bumped.
  - [ ] Ensure formatting and linting steps pull `rustfmt`/`clippy` from the pinned stable channel.
  - [ ] Update cached toolchain layers or containers to include the stable version before the release branch is cut.
- [ ] **Benchmarks & performance tracking**
  - [ ] Re-run benchmark suites after toolchain bumps to compare regressions.
  - [ ] Update baseline metrics stored in `bench/` artefacts or observability dashboards.
  - [ ] Communicate any performance deltas to stakeholders and capture follow-up tasks.

Once every item is checked, announce the toolchain status in the release communication channel and monitor post-merge CI for regressions.
