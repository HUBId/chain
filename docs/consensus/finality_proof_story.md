# Finality Proof Story

This ADR documents how consensus finality proofs incorporate validator evidence
and how verifiers reject tampering with the VRF or quorum material.

## Public Input Schema

Consensus proofs expose the following public inputs:

| Field | Description |
| --- | --- |
| `block_hash` | 32-byte hash of the proposed block. |
| `round` | BFT round identifier. |
| `epoch` | Epoch counter anchoring the fork-choice window. |
| `slot` | Slot (view) inside the epoch. |
| `leader_proposal` | Must equal `block_hash`. |
| `quorum_threshold` | Minimum voting power required for quorum. |
| `quorum_bitmap_root` | Merkle root of the prevote bitmap. |
| `quorum_signature_root` | Merkle root of aggregated vote signatures. |
| `vrf_entries[].randomness` | VRF randomness transcript emitted by each participating validator. |
| `vrf_entries[].pre_output` | VRF pre-output commitments paired with the randomness element. |
| `vrf_entries[].proof` | Raw Schnorrkel VRF proofs for the randomness/pre-output pair. |
| `vrf_entries[].public_key` | Validator VRF public keys that authored the transcript. |
| `vrf_entries[].poseidon.{digest,last_block_header,epoch,tier_seed}` | Poseidon transcript inputs that tie the validator metadata to the `block_hash`. `last_block_header` must equal the certificate `block_hash`, while each entry's `epoch` string mirrors the top-level `epoch` counter. |
| `witness_commitments[]` | Module witness commitments included in the block. |
| `reputation_roots[]` | Pre/post reputation ledger roots. |
| `vrf_entry_count` | Declares how many transcripts populate `vrf_entries[]`. |
| `witness_commitment_count` | Cardinality of the witness commitment vector. |
| `reputation_root_count` | Cardinality of the reputation root vector. |
| `vrf_output_binding` | Poseidon fold of `block_hash` with every VRF pre-output digest. |
| `vrf_proof_binding` | Poseidon fold of `block_hash` with every VRF proof blob. |
| `witness_commitment_binding` | Poseidon fold of `block_hash` with each witness commitment digest. |
| `reputation_root_binding` | Poseidon fold of `block_hash` with the reputation tree digests. |
| `quorum_bitmap_binding` | Poseidon commitment tying the prevote bitmap root to the `block_hash`. |
| `quorum_signature_binding` | Poseidon commitment tying the aggregated signature root to the `block_hash`. |

All metadata vectors must be non-empty; empty VRF transcripts, witness
commitments, or reputation roots are treated as forged data. The verifier also
expects each digest to be a 32-byte hexadecimal encoding (VRF proofs remain
variable-length Schnorrkel transcripts) and will abort if any quorum root uses
an invalid encoding. Validator public keys are exported as 32-byte hex strings
and undergo the same validation before entering the circuit.

Simnet fixtures and associated tooling now synthesise complete VRF transcript
objects that mirror this shape. Every entry includes the validator's randomness,
pre-output, proof bytes, public key, and Poseidon tuple bound to the certificate
`block_hash`/`epoch`, keeping the documentation examples aligned with the
on-chain metadata.

Legacy projections such as `vrf_outputs[]`/`vrf_proofs[]` remain available to the
RPC layer for a transition period. They are derived directly from
`vrf_entries[].pre_output` and `vrf_entries[].proof` so that downstream tooling
can continue to consume the flatter shape while migrating to the richer
transcript objects.

Every proof must supply the same number of VRF transcripts.  The STWO circuit
enforces this relationship, replays the Schnorrkel verification for each
transcript, and constrains the `vrf_entry_count` field so it exactly matches the
trace segment lengths for each vector inside the transcript tuple. Replaying the
VRF verification binds every `vrf_proof` to its associated Poseidon
`vrf_output`/pre-output so a prover cannot reshuffle raw transcripts or tweak
the proof bytes without breaking the AIR. In addition, the binding commitments
above are recomputed inside the circuit by folding the `block_hash` with each
metadata list using the Poseidon permutation. Any attempt to alter a VRF digest,
witness commitment, public key, or quorum root without also recomputing the
corresponding binding immediately violates the AIR relations.

## Verifier Responsibilities

The STWO and Plonky3 verifiers now lean on the circuit guarantees above. They
still reject malformed encodings up front, but once the transcript material
passes basic shape checks the verifiers rely on the AIR to recompute Poseidon
bindings and to re-run the Schnorrkel VRF checks that tie each proof to its
output. Consensus proofs therefore fail as soon as a `vrf_proof` diverges from
its `vrf_output`, even if the tampering preserves lengths and other superficial
metadata.

## Tamper Tests

`tests/consensus/consensus_proof_integrity.rs` and the backend-focused unit
tests in `prover/prover_stwo_backend/src/backend.rs` now tamper with valid VRF
transcripts to prove the strengthened binding. The suites swap two
`vrf_proof` blobs while leaving the outputs untouched and flip an individual
proof byte without altering lengths. Both Plonky3 and STWO verifiers reject the
tampered payloads, and the AIR-level tests cover the same scenarios to catch
regressions before they reach production harnesses.

