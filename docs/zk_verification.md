# Plonky3 Verification Path in RPP

## Overview
The RPP verifier rebuilds the exact Plonky3 configuration used by the prover and
invokes `p3_uni_stark::verify` directly. The entry point
`VerifierContext::verify_with_encoded` reconstructs the `CircuitStarkConfig`,
deserialises the STARK proof, decodes the canonical public inputs, and then calls
the upstream verifier before rebuilding metadata for post-verification checks.【F:prover/plonky3_backend/src/lib.rs†L2049-L2195】

## Verifier Reconstruction
All verifier-side resources are derived from the embedded
`StarkVerifyingKey`. The context rebuilds the FRI parameters, PCS/MMCS
configuration, challenger type, and AIR handle via `CircuitConfigBuilder` so the
prover and verifier share identical type aliases and flags. The key’s AIR handle
is reused to decode canonical inputs into concrete public values, and any
unsupported AIR aborts with an explicit backend error.【F:prover/plonky3_backend/src/lib.rs†L2059-L2146】

## Canonical Public Inputs
`compute_commitment_and_inputs` encodes RPP’s canonical public inputs, producing
both the Fiat–Shamir commitment string and the JSON payload that the verifier
replays. The verifier re-parses this canonical representation to recover the
circuit-specific public values before invoking Plonky3, ensuring UTXO roots,
block digests, and other ledger data remain deterministic across light clients
and pruned replicas.【F:prover/plonky3_backend/src/lib.rs†L2148-L2173】【F:prover/plonky3_backend/src/public_inputs.rs†L1-L120】

## Transcript Specification
After upstream verification succeeds, the backend replays the challenger to
capture the verifier’s Fiat–Shamir transcript. `TranscriptSnapshot` records the
extension-field challenges (`alpha`, `zeta`, PCS `alpha`), FRI round challenges,
queried indices, and stage checkpoints that encode pruning-sensitive digests.
`replay_challenger_transcript` mirrors Plonky3’s observation order so any
metadata tampering is caught by comparing stored and recomputed transcripts.【F:prover/plonky3_backend/src/lib.rs†L984-L1107】【F:prover/plonky3_backend/src/lib.rs†L1613-L1768】

## Error Mapping and Logging
Verifier failures from Plonky3 are translated into descriptive `BackendError`
variants that call out invalid proof shapes, PCS opening mismatches, constraint
violations, and ZK randomisation issues. Structured logging surfaces transcript
commitments, degrees, challenge limbs, and checkpoint states so operators can
trace failing transcripts without relying on auxiliary hashes.【F:prover/plonky3_backend/src/lib.rs†L62-L115】【F:prover/plonky3_backend/src/lib.rs†L2140-L2195】【F:prover/plonky3_backend/src/lib.rs†L2499-L2523】

## RPP Module Integration
RPP proofs serialise backend metadata via `ProofMetadata`, exposing canonical
inputs, transcript snapshots, and security settings to wallets and pruning
pipelines. Conversion helpers validate limb lengths, checkpoint ordering, and
stage labels before rehydrating backend types, ensuring Timetoke, reputation,
and pruning modules can replay the verifier transcript deterministically without
additional hashing layers.【F:rpp/proofs/plonky3/proof.rs†L35-L210】【F:rpp/proofs/plonky3/proof.rs†L246-L345】

## Test Coverage and Troubleshooting
Backend consensus tests exercise positive and negative scenarios, including
canonical-input mismatches, transcript checkpoint tampering, GPU flag flips, and
security parameter drift. RPP transaction tests round-trip proofs, reject
metadata and commitment tampering, and confirm transcript exposure for client
parsing. When debugging failures, inspect the structured logs for challenge
limbs and checkpoints, and cross-check the serialized metadata against the
schema to ensure client-side replay matches backend expectations.【F:prover/plonky3_backend/tests/consensus.rs†L1000-L1188】【F:rpp/proofs/plonky3/tests.rs†L200-L360】【F:tests/plonky3_transaction_roundtrip.rs†L40-L110】
