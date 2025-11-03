# Consensus Proof Regression Catalog

This catalog tracks regression tests that protect the consensus proof pipeline.
Each entry records the intent of the test and the current outcome.

| Test | Scenario | Result |
| --- | --- | --- |
| `consensus_verification_rejects_vrf_tampering` (STWO) | Mutates the VRF output commitment before verification. | ✅ Ensures verification fails when the VRF output diverges from the proof payload. |
| `consensus_verification_rejects_quorum_bitmap_tampering` (STWO) | Flips a bit in the quorum bitmap Merkle root. | ✅ Ensures verification fails when the quorum evidence root is altered. |
| `consensus_verification_rejects_tampered_vrf_randomness` (Plonky3) | Corrupts the VRF randomness array exposed through consensus public inputs. | ✅ Fails validation because the sanitized VRF bindings no longer match. |
| `consensus_verification_rejects_tampered_quorum_digest` (Plonky3) | Replaces the quorum bitmap digest in the consensus bindings map. | ✅ Fails validation because the quorum binding digest check detects the drift. |

The STWO suite lives in `prover/prover_stwo_backend` and runs with
`cargo test -p prover-stwo-backend`.【F:prover/prover_stwo_backend/src/backend.rs†L1193-L1334】
The Plonky3 coverage mirrors those manipulations in
`prover/plonky3_backend/tests/consensus.rs`.【F:prover/plonky3_backend/tests/consensus.rs†L1-L176】

All four scenarios are wired into the Phase 2 test matrix via
`cargo xtask test-consensus-manipulation`—set `XTASK_FEATURES="backend-plonky3"` to
execute both backend suites in one run.【F:xtask/src/main.rs†L70-L123】
