# Changelog

# 2025-10-20

- Reintegrate the vendored STWO prover as an optional Rust nightly path while keeping the stable workspace verifier-only.
- Add compile-time guard rails that emit “STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). Build without these features or use Nightly.” across all crates that forward the `prover-stwo` feature.
- Extend the node validation dispatch so nightly builds prove transactions via STWO before falling back to the stable RPP-STARK verifier path.
- Introduce nightly-only smoke tests under `rpp/node/tests/prover_nightly_smoke.rs` to ensure proofs verify and remain deterministic.
- Split CI into blocking stable and nightly workflows; the stable job runs both default and `backend-rpp-stark` matrices, while the nightly job builds/tests/clippy/fmt on the prover feature set and publishes the resulting binary plus SHA256.
- Document the new build profiles and compatibility matrix covering the nightly boundary.

## 2025-10-12

- Pin toolchain to Rust 1.79.0, add stable CI and Nightly scan (warn-mode). No code changes.
- Stable CI now passes cleanly on Rust 1.79.0 with no remaining `edition2024` opt-ins; see `docs/STABLE_MIGRATION_REPORT.md` for ongoing verification.
- Refresh release and migration documentation to describe the stable workflow and link to the new verification report.
