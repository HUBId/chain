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

Every proof must supply the same number of VRF outputs and proofs.  The STWO
circuit enforces this relationship and verifies that the proofs are correctly
formatted Schnorrkel transcripts.

## Verifier Responsibilities

The STWO verifier now re-computes the public input field elements from the
`ConsensusPublicInputs` structure.  Any drift between the supplied inputs and
the proof payload causes verification to fail.  The verifier also checks that
quorum roots are non-empty digests and that VRF proofs match the number of VRF
outputs bundled in the certificate metadata.

## Tamper Tests

`prover_stwo_backend` includes regression tests that intentionally mutate the
VRF output vector and the quorum bitmap root.  Both mutations are detected by
`verify_consensus`, ensuring that corrupted public inputs trigger a failure.

