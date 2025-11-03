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
expects each digest to be a 32-byte hexadecimal encoding and now enforces that
every VRF proof encodes exactly `crate::vrf::VRF_PROOF_LENGTH` bytes. Truncated
or oversized transcripts are rejected before the prover ever sees them, and the
verifier will abort if any quorum root uses an invalid encoding. Validator
public keys are exported as 32-byte hex strings and undergo the same validation
before entering the circuit.

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

Every proof must supply the same number of VRF transcripts. The STWO circuit now
mirrors that contract inside the AIR: it replays the Schnorrkel verification for
each transcript, constrains the `vrf_entry_count` field so it exactly matches the
trace segment lengths for every transcript component, and links the flattened
public inputs to the witness columns. The AIR enforces that each
`vrf_entries[].{randomness,pre_output,proof,public_key,poseidon.*}` value equals
the corresponding trace element by reading the public inputs and the trace with
matching offsets in the summary row. The same approach ties the quorum bitmap
and quorum signature roots to the binding segments that fold them with the
`block_hash`. Together with the Poseidon bindings, any attempt to alter a VRF
digest, witness commitment, public key, or quorum root without recomputing the
trace violates the AIR.

## Verifier Responsibilities

The Plonky3 and STWO verifiers now benefit from the strengthened AIR. They still
perform the legacy host-side shape checks, but the proof verification path now
fails whenever the prover tampers with the public VRF transcripts or quorum
roots. This behaviour is observable in the new regression suite
`tests/consensus/consensus_proof_tampering.rs`, which mutates the public VRF
randomness and quorum bitmap roots while keeping the proof commitments coherent.
Both backends reject the tampered artifacts, demonstrating that the AIR bindings
and the verifier cross-checks agree on the public input integrity.

## Tamper Tests

Regression coverage includes both the legacy serializer checks and the new
public-input tampering scenarios. The existing suites
(`tests/consensus/consensus_proof_integrity.rs` and the backend-focused coverage
under `prover/prover_stwo_backend/src/backend.rs`) exercise witness-level
manipulations. The new integration suite
`tests/consensus/consensus_proof_tampering.rs` mutates VRF randomness and quorum
roots directly inside the public input vectors and asserts that
`verify_consensus` fails for both the STWO and Plonky3 backends. These tests
serve as the Phase 2 regression anchor referenced in the
[Malachite BFT architecture plan](../malachite_bft_architecture.md#acceptance-kriterien-vrf-quorum-proofs).

