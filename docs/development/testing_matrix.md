# Testing matrix coverage

The Firewood storage feature combinations and zk backend permutations run in CI through the job IDs listed below. Job IDs are used to make it easy to keep the table in sync with `.github/workflows/ci.yml`.

| Combination | Feature flags | CI jobs (job IDs) | Expected runtime (CI) | Notes |
| --- | --- | --- | --- | --- |
| Default storage / default backend | – | firewood-unit, firewood-ffi-go, firewood-giant-node, unit-suites, integration-workflows, simnet-smoke | ≈35–45 min | Baseline coverage that exercises the standard branch factor, default hasher, and the default prover/wallet build. |
| io-uring storage backend | io-uring | firewood-unit, firewood-ffi-go, firewood-giant-node | ≈12–18 min | Validates async I/O for Firewood at the unit, FFI, and giant-node levels. |
| Branch factor 256 hashing | branch_factor_256 | firewood-unit | ≈6–10 min | `cargo xtask test-firewood` runs the dedicated branch-factor pass even when the matrix entry injects different feature flags. |
| Ethereum-compatible hashing | ethhash | firewood-unit, firewood-ffi-go | ≈10–15 min | Ensures Firewood and its FFI stay compatible with the Ethereum hash functions. |
| Branch factor 256 + Ethereum hashing | branch_factor_256, ethhash | firewood-unit, firewood-ffi-go | ≈10–16 min | Verifies the combined hashing mode before merging regenerated fixtures. |
| RPP-STARK backend for Firewood | backend-rpp-stark | firewood-ffi-go, firewood-giant-node | ≈18–25 min | Confirms the zk backend bindings compile and the giant-node regression still holds under `backend-rpp-stark`. |
| STWO production backend | prod, prover-stwo | unit-suites, integration-workflows, simnet-smoke | ≈45–55 min | Runs all `cargo xtask` validation suites with the production prover enabled. |
| STWO backend with Plonky3 verifier | prod, prover-stwo, backend-plonky3 | unit-suites, integration-workflows, simnet-smoke | ≈50–60 min | Exercises the Plonky3 verifier path alongside the STWO prover in every xtask suite. |
| Branch factor 256 + io-uring with pruning (default backend) | branch_factor_256, io-uring, pruning enabled | combined-feature-lanes | ≈45–55 min | Runs the combined lane (`cargo xtask test-combined-lane`) to ensure storage feature gates, pruning checks, and core smokes are exercised together. |
| Branch factor 256 + io-uring with pruning (backend-rpp-stark) | branch_factor_256, io-uring, backend-rpp-stark, pruning enabled | combined-feature-lanes | ≈50–60 min | Mirrors the combined storage/pruning lane with `backend-rpp-stark` enabled to guard against backend-specific regressions. |

## Pruned snapshot zk recovery coverage

`cargo xtask test-integration` exercises the pruned snapshot round-trip in both the default and `backend-rpp-stark` matrix rows. The `wallet_snapshot_round_trip_*` cases prune state, take a disk snapshot, restore it, verify pruning proofs, and ensure the mempool WAL replays consistently.

To rerun locally:

- Default backend: `cargo test -p rpp-chain --locked --test pruning_cross_backend -- wallet_snapshot_round_trip_default_backend`
- RPP-STARK backend: `cargo test -p rpp-chain --locked --features backend-rpp-stark --test pruning_cross_backend -- wallet_snapshot_round_trip_rpp_stark_backend`
