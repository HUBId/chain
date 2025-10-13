# Changelog

## 2025-10-12

- Pin toolchain to Rust 1.79.0, add stable CI and Nightly scan (warn-mode). No code changes.
- Stable CI now passes cleanly on Rust 1.79.0 with no remaining `edition2024` opt-ins; see `docs/STABLE_MIGRATION_REPORT.md` for ongoing verification.
- Refresh release and migration documentation to describe the stable workflow and link to the new verification report.
