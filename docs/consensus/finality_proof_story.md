# Finality Proof Story

This ADR documents how consensus finality proofs incorporate validator evidence
and which verification gaps still remain while the Phase 2 enforcement work is
under construction.

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
before entering the circuit. **At the current milestone these are format-only
checks; the verifiers do not yet recompute VRF transcripts or quorum thresholds
from first principles.**

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

Every proof must supply the same number of VRF transcripts. The STWO circuit and
its Plonky3 counterpart still expose the public input bindings but **do not yet
enforce the VRF transcript replays or quorum thresholds in the constraint
system**. The upcoming Phase 2 work will wire the AIR gadgets and Plonky3 custom
gates that recompute each transcript and fold the quorum material back into the
trace so tampering attempts are caught inside the proof system rather than by
shape checks alone.

## Verifier Responsibilities

Both verifiers continue to perform the legacy host-side shape checks: they
validate byte lengths, reject empty vectors, and confirm that public input
encodings adhere to the schema above. **They currently stop short of recomputing
the VRF transcripts, Poseidon bindings, or quorum thresholds**, which means a
prover that forges coherent digests could still bypass the host-side checks
until the constraint-layer enforcement lands. Capturing the full VRF replay and
quorum math inside the verifiers remains outstanding Phase 2 work.

## Tamper Tests

The regression suites still focus on serialization and shape validation. They
exercise malformed encodings and missing metadata but **do not yet mutate VRF
or quorum digests in a way that survives the current format guards**. Dedicated
tamper scenarios will be introduced alongside the constraint-layer work so that
`verify_consensus` fails whenever forged transcripts or quorum roots reach the
verifiers. Those tests are tracked with the engineering tasks linked below and
will become the Phase 2 regression anchors referenced in the
[Malachite BFT architecture plan](../malachite_bft_architecture.md#acceptance-kriterien-vrf-quorum-proofs).

> [!TODO]
> **Phase 2 enforcement tracking.**
> - [ENG-742 – Constraint-layer VRF/quorum enforcement](../../roadmap_implementation_plan.md#eng-742-constraint-layer-vrfquorum-enforcement)
>   wires the missing AIR gadgets and Plonky3 gates that replay transcripts and enforce quorum math.
> - [ENG-743 – Tamper regression hardening](../../roadmap_implementation_plan.md#eng-743-tamper-regression-hardening)
>   extends the test suites so forged VRF/quorum digests are rejected once the constraint work lands.

