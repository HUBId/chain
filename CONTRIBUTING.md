# Contributing

## Toolchains & Local Workflows

- **Stable default (required)**
  - Install the pinned stable toolchain with `rustup toolchain install 1.79.0`.
  - `rustup` will auto-select it through `rust-toolchain.toml`; ensure the `rustfmt` and `clippy` components are added (`rustup component add --toolchain 1.79.0 rustfmt clippy`).
  - CI runs `cargo +1.79.0 clippy --workspace --all-features -D warnings`; mirror this locally before submitting a PR.
- **Nightly scan (optional checks)**
  - Run `scripts/ci/stable_scan` to generate `docs/STABLE_MIGRATION_REPORT.md` when auditing for regressions.
  - The GitHub Actions workflow publishes the same report in warn mode; once it stays empty we will flip it to blocking.

- **Storage stability snapshot**
  - Review [docs/STORAGE_STABLE_REPORT.md](docs/STORAGE_STABLE_REPORT.md) for the latest Firewood MSRV audit and CI notes.
  - Update the report whenever storage crates gain new features or dependencies so operators can track stable readiness.

## Lokale Entwicklung

Use the stable toolchain commands directly when iterating:

```bash
cargo +1.79.0 build --workspace --all-features
cargo +1.79.0 test --workspace --all-features
cargo +1.79.0 clippy --workspace --all-features -D warnings
cargo +1.79.0 fmt --all -- --check
```

The helper scripts under `scripts/` remain available, but the explicit commands above match the new stable CI configuration.
If these commands fail today, check `docs/STABLE_MIGRATION_REPORT.md`—the report should stay empty now that the workspace builds on stable 1.79 without `edition2024` opt-ins.

## Backend Implementation Conventions

- New proving/storage backends must live under dedicated feature flags (e.g. `backend-plonky3`) and default to disabled unless production-ready.
- Implement backend-specific configuration in `config/` and document required keys in the README backend section.
- Provide integration tests or simulations under `tests/` or `rpp/sim/` that exercise the backend in isolation.
- Update CI matrices to include opt-in coverage for the new backend and describe the workflow in the PR summary.

## Troubleshooting

- **Toolchain mismatch errors**
- `error: toolchain '1.79.0' is not installed`: run `rustup toolchain install 1.79.0`.
- `error: component 'rustfmt' for target 'x86_64-unknown-linux-gnu' is unavailable`: run `rustup component add --toolchain 1.79.0 rustfmt clippy`.
- If the stable scan reports new findings, investigate the referenced files and schedule a cleanup PR before promoting the warn gate to blocking.
