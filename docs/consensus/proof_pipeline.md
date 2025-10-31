# Consensus Proof Pipeline

The consensus proving pipeline now publishes structured metadata alongside the
existing quorum inputs.  Consensus certificates include deterministic digests
that are forwarded into the prover witness envelope and the public input vector
for verification.

The metadata captures three critical views of validator participation:

- **VRF outputs** – the randomness beacons that determine validator eligibility
  for the current round.  These digests are exported as 32-byte commitments and
  embedded into the consensus proof's public inputs so that verifiers can ensure
  the witness was generated for the same validator set advertised by the
  runtime.
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
The STWO backend reconstructs the public-input field elements from the same
metadata, ensuring that verification fails if any digest diverges from the block
state observed by the runtime.  The integration tests in
`rpp/consensus/tests/consensus_proof_roundtrip.rs` exercise the new metadata path
and guarantee that encode/decode operations retain the structured inputs.
