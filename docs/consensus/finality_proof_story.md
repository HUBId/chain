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
| `vrf_outputs[]` | VRF output commitments, one per participating validator. |
| `vrf_proofs[]` | Raw Schnorrkel VRF proofs paired with the outputs. |
| `witness_commitments[]` | Module witness commitments included in the block. |
| `reputation_roots[]` | Pre/post reputation ledger roots. |

All metadata vectors must be non-empty; empty VRF digests, witness commitments,
or reputation roots are treated as forged data. The verifier also expects each
entry to be a 32-byte hexadecimal digest and will abort if any quorum root uses
an invalid encoding.

Every proof must supply the same number of VRF outputs and proofs.  The STWO
circuit enforces this relationship and verifies that the proofs are correctly
formatted Schnorrkel transcripts.

## Verifier Responsibilities

Both the STWO and Plonky3 verifiers re-compute the public input field elements
from the structured witness payload. Any drift between the supplied inputs and
the proof metadata causes verification to fail. The implementations enforce that
quorum roots decode to 32-byte digests, that the VRF output/proof vectors are
non-empty and length-matched, and that the witness and reputation digests
reflect exactly what the runtime committed to.

## Tamper Tests

`tests/consensus/consensus_proof_integrity.rs` fabricates consensus proofs and
tamper with the VRF metadata and quorum roots. Both the STWO and Plonky3
verifiers reject the forged payloads, mirroring the lower-level unit tests in
`rpp/proofs/stwo/tests/consensus_metadata.rs` and `rpp/proofs/plonky3/tests.rs`
that cover the individual circuit invariants.

