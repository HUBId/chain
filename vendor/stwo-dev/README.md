# STWO Developer Vendor Bundle

This directory stores a curated snapshot of StarkWare's STWO prover workspace as
used by Firewood. Sources are segmented under `0.1.1/staging/` so we can audit
individual crates, regenerate manifests, and track large binary assets.

## Layout

- `0.1.1/staging/crates/stwo`: Main prover crate with SIMD backends and
  Criterion benches under `benches/`.
- `0.1.1/staging/crates/constraint-framework`: Shared constraint utilities
  consumed by the prover.
- `0.1.1/manifest`: Hash listings for every extracted file plus the chunk plan.
- `0.1.1/logs`: Timestamped refresh logs for provenance tracking.

## Running the vendored benches

The Criterion harnesses live in `0.1.1/staging/crates/stwo/benches/`. To execute
one of them through the Firewood workspace, ensure the `std` and `prover`
features are enabled and invoke Cargo from the repository root:

```bash
cargo bench -p stwo --features "std prover" --bench merkle
```

Cargo will rebuild the vendored crate from `vendor/stwo-dev/0.1.1/staging` and
write results to `target/criterion/`. See the crate-level
[`README.md`](0.1.1/staging/crates/stwo/README.md) for a rundown of the available
bench targets and additional Criterion tips.

## Refreshing the vendor snapshot

1. Download and extract the upstream workspace into a temporary staging area.
2. Synchronise the desired crates into `0.1.1/staging/` while pruning build
   artefacts (e.g. `.git/`, `target/`).
3. Recompute the manifest with `scripts/update_vendor_manifest.py stwo-dev 0.1.1`
   (or the equivalent helper) so that `manifest/final_file_list.txt` reflects the
   new tree and append a short note to `logs/update_manifest.log` describing the
   refresh.

All hashes in the manifest use SHA-256 and file sizes are recorded in bytes to
make diffs easy to audit.
