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
| `vrf_entries[].poseidon.{randomness,pre_output,proof,public_key}` | Poseidon bindings that tie each transcript component to the `block_hash`. |
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

Legacy projections such as `vrf_outputs[]`/`vrf_proofs[]` remain available to the
RPC layer for a transition period. They are derived directly from
`vrf_entries[].pre_output` and `vrf_entries[].proof` so that downstream tooling
can continue to consume the flatter shape while migrating to the richer
transcript objects.

Every proof must supply the same number of VRF transcripts.  The STWO circuit
enforces this relationship, verifies that the proofs are correctly formatted
Schnorrkel transcripts, and constrains the `vrf_entry_count` field so it exactly
matches the trace segment lengths for each vector inside the transcript tuple.
In addition, the binding commitments above are recomputed inside the circuit by
folding the `block_hash` with each metadata list using the Poseidon permutation.
Any attempt to alter a VRF digest, witness commitment, public key, or quorum
root without also recomputing the corresponding binding immediately violates the
AIR relations.

## Verifier Responsibilities

Today the STWO and Plonky3 verifiers only repeat the lightweight
format/structure checks that the witness loader performs. They confirm that the
VRF output/proof vectors are non-empty, length-matched, and filled with
32-byte-encoded digests, and that the witness and reputation lists provide the
declared number of entries. These checks prevent obviously malformed payloads
from entering the recursion path, but they do not yet bind the VRF transcripts
or quorum commitments to the block context.

> **Gap – VRF/Quorum constraints pending:** Phase‑2 will extend the circuits to
> re-derive the VRF transcripts and quorum roots inside the AIR so the verifiers
> can reject semantically valid-looking forgeries. Progress is tracked in the
> blueprint backlog under [`proofs.plonky3_vendor_backend`](../../rpp/proofs/blueprint/mod.rs#L133-L155). The section returns to
> “complete” once all acceptance criteria are met:
> 
> - the Phase‑2 circuit updates bind VRF transcripts and quorum roots to the
>   block hash;
> - the verifier APIs expose and enforce the new constraints end-to-end; and
> - regression suites cover positive/negative paths with the new tamper tests
>   described for Phase‑2 (circuit updates plus fresh scenarios in the production
>   test plan).

## Tamper Tests

`tests/consensus/consensus_proof_integrity.rs` currently limits itself to
tampering with the vector sizes and digest encodings; both verifiers catch these
format violations. The lower-level unit suites in
`rpp/proofs/stwo/tests/consensus_metadata.rs` and
`rpp/proofs/plonky3/tests.rs` exercise the same guards. Phase‑2 will add
tampering scenarios that mutate VRF transcripts and quorum Merkle data without
breaking the encoding so the updated circuits and verifiers can prove they
reject realistic attacks, backed by the planned circuit changes and new tests
listed in the production test plan.

