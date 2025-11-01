# Consensus Proof Regression Catalog

This catalog tracks regression tests that protect the consensus proof pipeline.
Each entry records the intent of the test and the current outcome.

| Test | Scenario | Result |
| --- | --- | --- |
| `consensus_verification_rejects_vrf_tampering` | Mutates the VRF output commitment before verification. | ✅ Ensures verification fails when the VRF output diverges from the proof payload. |
| `consensus_verification_rejects_quorum_bitmap_tampering` | Flips a bit in the quorum bitmap Merkle root. | ✅ Ensures verification fails when the quorum evidence root is altered. |

Both tests live in `prover/prover_stwo_backend` and run as part of the standard
`cargo test -p prover-stwo-backend` invocation.【F:prover/prover_stwo_backend/src/backend.rs†L1000-L1053】
