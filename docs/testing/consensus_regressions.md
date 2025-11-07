# Consensus Proof Regression Catalog

This catalog tracks regression tests that protect the consensus proof pipeline.
Each entry records the intent of the test and the current outcome.

| Scenario | STWO backend | Plonky3 backend | Gap |
| --- | --- | --- | --- |
| VRF commitment tampering | ✅ `consensus_verification_rejects_vrf_tampering` | ✅ `consensus_verification_rejects_tampered_vrf_randomness` | — |
| Quorum bitmap tampering | ✅ `consensus_verification_rejects_quorum_bitmap_tampering` | ✅ `consensus_verification_rejects_tampered_quorum_digest` | — |
| Witness commitment tampering | ✅ `stwo_rejects_public_witness_commitment_tampering` | ✅ `consensus_verification_rejects_tampered_witness_commitment` | — |
| Reputation root tampering | ✅ `stwo_rejects_public_reputation_root_tampering` | ✅ `consensus_verification_rejects_tampered_reputation_root` | — |

✅ in the STWO column denotes shipped coverage in `prover/prover_stwo_backend`, executed with
`cargo test -p prover-stwo-backend`. The Plonky3 regression suite exercises the same scenarios in
`prover/plonky3_backend/tests/consensus.rs` and runs with `cargo test -p prover-plonky3-backend`.

The STWO suite lives in `prover/prover_stwo_backend` and runs with
`cargo test -p prover-stwo-backend`.【F:prover/prover_stwo_backend/src/backend.rs†L1193-L1334】
Plonky3 mirrors consensus verification coverage in
`prover/plonky3_backend/tests/consensus.rs`.【F:prover/plonky3_backend/tests/consensus.rs†L600-L720】

All six scenarios are wired into the Phase 2 test matrix via
`cargo xtask test-consensus-manipulation`—set `XTASK_FEATURES="backend-plonky3"` to
execute both backend suites in one run.【F:xtask/src/main.rs†L70-L123】
