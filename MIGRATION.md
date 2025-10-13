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

## Switching from Nightly to Stable

Use the following checklist to track the stable readiness work:

- [ ] **Toolchain**
  - [ ] Run the full validation suite on `nightly-2024-06-20` to capture baseline behaviour.
  - [ ] Verify the codebase compiles with the target stable (`1.79`) locally and in CI sandboxes.
  - [ ] Update `rust-toolchain.toml` to reference the stable channel, or remove it if default `rustup` overrides are acceptable.
- [ ] **Feature flags & crates**
  - [ ] Audit `Cargo.toml` and workspace members for `#![feature(...)]` attributes or nightly-only dependencies.
  - [ ] Gate unstable functionality behind cfg flags or replace it with stable equivalents.
  - [ ] Refresh documentation snippets and examples to avoid nightly-only syntax.
- [ ] **CI configuration**
  - [ ] Switch CI jobs (build, test, lint, docs) to the stable toolchain matrix.
  - [ ] Ensure formatting and linting steps pull `rustfmt`/`clippy` from the stable channel.
  - [ ] Update cached toolchain layers or containers to include the stable version.
- [ ] **Benchmarks & performance tracking**
  - [ ] Re-run benchmark suites under both nightly and stable toolchains to compare regressions.
  - [ ] Update baseline metrics stored in `bench/` artefacts or observability dashboards.
  - [ ] Communicate any performance deltas to stakeholders and capture follow-up tasks.

Once every item is checked, announce the migration timeline, merge the toolchain update, and monitor post-merge CI for regressions.
