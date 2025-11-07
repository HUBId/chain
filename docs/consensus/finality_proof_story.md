# Finality Proof Story

This ADR documents how consensus finality proofs incorporate validator evidence
and how the Phase 2 circuit enforcement now rejects forged VRF transcripts and
quorum digests.

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
expects each digest to be a 32-byte hexadecimal encoding and enforces that every
VRF proof encodes exactly `crate::vrf::VRF_PROOF_LENGTH` bytes. Truncated or
oversized transcripts are rejected before the prover ever sees them, and the
verifier will abort if any quorum root uses an invalid encoding. Validator
public keys are exported as 32-byte hex strings and undergo the same validation
before entering the circuit. The circuit bridge now recomputes each VRF entry
with Schnorrkel, folding the randomness back into the Poseidon sponge so only
authentic transcripts survive the witness conversion.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L308-L458】【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L420-L501】

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
replays each entry against the validator’s public key, derives randomness via
`vrf_verify`, and asserts that the witness epoch/header match the
certificate.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L420-L501】 The Plonky3 bridge mirrors the same
checks when materialising the backend witness, rejecting entries whose
Poseidon header, epoch, or tier seed deviate from the block hash or consensus
epoch.【F:prover/plonky3_backend/src/circuits/consensus.rs†L520-L585】 Any mismatch halts the proof before
constraint evaluation begins.

## Verifier Responsibilities

Both verifiers continue to perform the host-side shape checks—validating byte
lengths, rejecting empty vectors, and confirming that public input encodings
adhere to the schema above—but they now lean on the circuit layer for the
substantive security guarantees. The STWO consensus circuit computes vote
totals, enforces quorum thresholds, recomputes Poseidon binding folds, and feeds
the verified VRF outputs back into the public inputs so forged transcripts or
quorum digests cannot satisfy the constraints.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L300-L364】【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L512-L586】【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L1068-L1135】 On the Plonky3 path the
`ConsensusCircuit` wrapper reconstructs the AIR trace using the sanitized VRF
entries, Poseidon sponge fold, and quorum bindings; any divergence between the
public inputs and the recomputed digests aborts verification.【F:prover/plonky3_backend/src/circuits/consensus.rs†L600-L690】【F:prover/plonky3_backend/src/circuits/consensus.rs†L1230-L1340】

## Tamper Tests

Regression coverage now mutates both the public inputs and payload metadata to
prove that forged VRF randomness, transcripts, bitmap digests, and signature
roots fail for STWO and Plonky3 alike. The workspace suite exercises the tamper
scenarios directly via `tests/consensus/consensus_proof_tampering.rs`, while the
backend packages mirror the same manipulations in their native test harnesses;
`cargo xtask test-consensus-manipulation` wires these suites into CI and
nightly jobs.【F:tests/consensus/consensus_proof_tampering.rs†L100-L320】【F:prover/plonky3_backend/tests/consensus.rs†L520-L690】【F:xtask/src/main.rs†L78-L125】 The acceptance checklists and roadmap entries below
track ENG‑742/ENG‑743 as delivered, using these tests as the regression anchors.

