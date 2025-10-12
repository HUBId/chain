# Changelog

## 2025-10-12

- Pin toolchain to Rust 1.79.0, add stable CI and Nightly scan (warn-mode). No code changes.
- Stable CI currently reports warnings for crates that still opt into `edition2024` (workspace manifests and the `malachite` dependency); see `docs/STABLE_MIGRATION_REPORT.md`.
