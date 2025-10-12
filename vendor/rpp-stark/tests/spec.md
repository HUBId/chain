# Prover/Verifier Determinism Specification

This repository currently ships interface-only modules. Implementations are
expected to satisfy the following behavioural contracts once wired in:

## Deterministic Proving
- `generate_proof` must be deterministic for a fixed combination of
  `ProofKind`, public inputs, witness blob and `ProverContext`.
- VRF commitments embedded inside the `proof::types::Proof` payload must be
  derived solely from prover-side state; no verifier challenge is allowed during the
  generation phase.

## Envelope and Size Checks
- Every produced `proof::types::Proof` must respect `MAX_PROOF_SIZE_BYTES` including
  metadata and body payload.
- Header lengths must match the serialized payload lengths documented in
  `public_inputs.rs` and the integrity digest must bind both segments.

## Verifier Requirements
- `Verifier::verify` must recompute transcript digests locally and compare
  them against the envelope without relying on prover responses.
- VRF challenges must be derived by the verifier independently using the
  commitments extracted via `Verifier::vrf_commitments`.

Test harnesses should capture these invariants through reproducible fixtures
that assert byte-for-byte equality of proof outputs and verify the maximum
size constraints.

## Post-Quantum VRF Specification

- `vrf_keygen`, `vrf_evaluate` and `vrf_verify` follow the contracts captured in
  `src/vrf/mod.rs` (no ambient randomness; transcript driven only).
- The transcript must begin with the domain tag `RPP-VRF-V1` and include the
  ordered sections enumerated in `VrfTranscriptSpec::SECTION_ORDER`.
- VRF outputs are normalized via BLAKE3-XOF with prefix `RPP-VRF-OUT` followed
  by rejection sampling until a uniform 32-byte value is obtained.
- Anti-grinding requires a commit-then-reveal protocol using
  `commit = H(vrf_output || round_id || pk)`; mismatches yield
  `ErrVrfCommitMismatch`.
- Leader selection accepts when `H(vrf_output || round_ctx) < T` (little-endian)
  and sorts multi-winner sets by `(vrf_output, pk)`.
- Chain configuration must expose `VRF_SWITCH_HEIGHT` (and optionally
  `VRF_SWITCH_EPOCH`) such that EC-VRF proofs after the switch emit
  `ErrVrfLegacyRejected`.
- VRF public inputs use the header layout in `PublicInputSerializationSpec::VRF_FIELDS`
  binding `pk`, PRF parameter digests and context identifiers.
- Test fixtures must cover determinism, bias detection, commit/reveal errors and
  pre/post-cutover validation as summarised in `VrfTestPlan`.
