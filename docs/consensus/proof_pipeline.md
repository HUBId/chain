# Consensus Proof Pipeline

The consensus proving pipeline now publishes structured metadata alongside the
existing quorum inputs.  Consensus certificates include deterministic digests
that are forwarded into the prover witness envelope and the public input vector
for verification.

The metadata captures several critical views of validator participation:

- **VRF outputs** – the randomness beacons that determine validator eligibility
  for the current round.  These digests are exported as 32-byte commitments and
  embedded into the consensus proof's public inputs so that verifiers can ensure
  the witness was generated for the same validator set advertised by the
  runtime.
- **VRF proofs** – Schnorrkel transcripts that justify the published VRF
  outputs.  The raw proofs are committed as byte-aligned public inputs so that
  tampering with the randomness can be detected by independent verifiers.
- **Epoch and slot context** – round metadata (epoch and slot) is surfaced next
  to the quorum threshold, ensuring that the proof cannot be replayed for a
  different fork-choice decision.
- **Quorum evidence roots** – Merkle roots for the pre-vote bitmap and the
  aggregated signature set are part of the public inputs.  The verifier rejects
  proofs where either root diverges from the signed quorum evidence supplied by
  the runtime, making quorum manipulation observable.
- **Witness commitments** – hashes of the module witness bundle that tie the
  STARK proof back to the block's auxiliary data (transaction, timetoke,
  reputation, and consensus witnesses).  Propagating these hashes prevents the
  prover from altering the witness bundle after computing the proof.
- **Reputation roots** – Merkle roots tracking the validator reputation ledger
  before and after consensus execution.  Including both roots enables verifiers
  to assert that the consensus proof was derived from the same ledger state as
  the block header.

`ConsensusCertificate::encode_witness` serialises the certificate together with
its `ConsensusProofMetadata` and wraps the payload in a typed witness envelope.
Both the STWO and Plonky3 backends reconstruct the public-input field elements
from the same metadata, ensuring that verification fails if any digest diverges
from the block state observed by the runtime. The regression tests in
`tests/consensus/consensus_proof_integrity.rs`,
`rpp/proofs/stwo/tests/consensus_metadata.rs`, and
`rpp/proofs/plonky3/tests.rs` keep the metadata guarantees honest by mutating
VRF bundles and quorum roots and asserting that the verifiers reject the forged
payloads.

> **Operations link:** Alert thresholds and on-call response guidance for the
> RPP-STARK verifier are documented in
> [operations/zk_backends.md](../operations/zk_backends.md).
