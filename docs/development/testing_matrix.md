# Testing matrix coverage

The Firewood storage feature combinations and zk backend permutations run in CI through the job IDs listed below. Job IDs are used to make it easy to keep the table in sync with `.github/workflows/ci.yml`.

| Combination | Feature flags | CI jobs (job IDs) | Notes |
| --- | --- | --- | --- |
| Default storage / default backend | – | firewood-unit, firewood-ffi-go, firewood-giant-node, unit-suites, integration-workflows, simnet-smoke | Baseline coverage that exercises the standard branch factor, default hasher, and the default prover/wallet build. |
| io-uring storage backend | io-uring | firewood-unit, firewood-ffi-go, firewood-giant-node | Validates async I/O for Firewood at the unit, FFI, and giant-node levels. |
| Branch factor 256 hashing | branch_factor_256 | firewood-unit | `cargo xtask test-firewood` runs the dedicated branch-factor pass even when the matrix entry injects different feature flags. |
| Ethereum-compatible hashing | ethhash | firewood-unit, firewood-ffi-go | Ensures Firewood and its FFI stay compatible with the Ethereum hash functions. |
| Branch factor 256 + Ethereum hashing | branch_factor_256, ethhash | firewood-unit, firewood-ffi-go | Verifies the combined hashing mode before merging regenerated fixtures. |
| RPP-STARK backend for Firewood | backend-rpp-stark | firewood-ffi-go, firewood-giant-node | Confirms the zk backend bindings compile and the giant-node regression still holds under `backend-rpp-stark`. |
| STWO production backend | prod, prover-stwo | unit-suites, integration-workflows, simnet-smoke | Runs all `cargo xtask` validation suites with the production prover enabled. |
| STWO backend with Plonky3 verifier | prod, prover-stwo, backend-plonky3 | unit-suites, integration-workflows, simnet-smoke | Exercises the Plonky3 verifier path alongside the STWO prover in every xtask suite. |
