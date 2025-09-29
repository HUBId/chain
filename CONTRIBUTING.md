# Contributing

## Toolchains & Local Workflows

- **Nightly-first path (current default)**
  - Ensure the repository's pinned `nightly-2024-06-20` toolchain is active. `rustup` selects it automatically via `rust-toolchain.toml`.
  - Install the matching components with `rustup component add --toolchain nightly-2024-06-20 rustfmt clippy`.
  - Use the helper scripts for consistency:
    - `scripts/build.sh [--release|--feature-set ...]` to compile.
    - `scripts/test.sh [flags]` to execute unit, integration, and doc tests.
  - Run `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings` before opening a PR.
- **Stable validation path (migration prep)**
  - Install the target stable release (currently `1.79`) with `rustup toolchain install 1.79.0`.
  - Mirror the nightly commands by prefixing with `RUSTUP_TOOLCHAIN=1.79.0` (or using `rustup run 1.79.0 ...`) to detect nightly-only dependencies.
  - Capture differences in output, formatting, or warnings and file migration issues in the tracking board referenced in `MIGRATION.md`.

## Backend Implementation Conventions

- New proving/storage backends must live under dedicated feature flags (e.g. `backend-plonky3`) and default to disabled unless production-ready.
- Implement backend-specific configuration in `config/` and document required keys in the README backend section.
- Provide integration tests or simulations under `tests/` or `rpp/sim/` that exercise the backend in isolation.
- Update CI matrices to include opt-in coverage for the new backend and describe the workflow in the PR summary.

## Troubleshooting

- **Toolchain mismatch errors**
  - `error: toolchain 'nightly-2024-06-20' is not installed`: run `rustup toolchain install nightly-2024-06-20`.
  - `error: component 'rustfmt' for target 'x86_64-unknown-linux-gnu' is unavailable`: install via `rustup component add --toolchain nightly-2024-06-20 rustfmt`.
  - `error: toolchain '1.79.0' is not installed` when testing the stable path: run `rustup toolchain install 1.79.0` and retry with `RUSTUP_TOOLCHAIN=1.79.0`.
- If builds succeed on nightly but fail on stable, cross-reference the checklist in `MIGRATION.md` and flag blocking nightly-only features.
