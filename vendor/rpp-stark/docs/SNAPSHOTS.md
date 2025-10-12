# Snapshot policy

Snapshots freeze deterministic proof artefacts so changes to the proof ABI or
critical encodings cannot slip in unnoticed. They mirror the byte-level layout of
the prover outputs and serve as regression fixtures for the verifier and the CI
snapshot guard.

## Locations

The repository hosts three snapshot families:

- `vectors/stwo/mini/*` – interoperable "golden" vectors shared with STWO.
- `tests/snapshots/*.snap` – canonical proof, Merkle, FRI and serialization
  fixtures used by unit and integration tests.
- `tests/fail_matrix/snapshots/*.snap` – negative fixtures capturing how the
  verifier reports malformed proofs.

## File reference

### STWO golden vector (interop)

- `vectors/stwo/mini/README.md` – background on the interop bundle and how the
  vector is produced.
- `vectors/stwo/mini/challenges.json` – Fiat–Shamir challenges for every proof
  phase.
- `vectors/stwo/mini/indices.json` – sorted query indices used by the openings.
- `vectors/stwo/mini/params.bin` – canonical parameter block referenced by the
  proof.
- `vectors/stwo/mini/proof.bin` – byte-for-byte proof envelope.
- `vectors/stwo/mini/proof_report.json` – verifier status report for
  `proof.bin`.
- `vectors/stwo/mini/public_digest.hex` – digest the verifier derives from the
  public inputs.
- `vectors/stwo/mini/public_inputs.bin` – canonical public-input payload.
- `vectors/stwo/mini/roots.json` – Merkle and FRI roots emitted by the prover.

### Canonical proof artefacts (`tests/snapshots`)

- `fri_end_to_end__fri_end_to_end_hisec_deep_proof.snap` – high-security FRI
  proof bytes for the deep configuration.
- `fri_end_to_end__fri_end_to_end_standard_proof.snap` – standard profile FRI
  proof bytes.
- `fri_proof_serialization__fri_proof_v1_bytes.snap` – serialization snapshot of
  a canonical `FriProof` structure.
- `merkle_roundtrip__merkle_aux_bin.snap` – auxiliary Merkle bundle encoding.
- `merkle_roundtrip__merkle_proof_bin.snap` – Merkle proof bytes for trace
  openings.
- `merkle_roundtrip__merkle_root_bin.snap` – canonical Merkle root bytes.
- `params_roundtrip__profile_hisec_hash.snap` – digest of the high-security
  parameter profile.
- `params_roundtrip__profile_hisec_params.snap` – serialized high-security
  parameter profile.
- `params_roundtrip__profile_x8_hash.snap` – digest of the default ×8 profile.
- `params_roundtrip__profile_x8_params.snap` – serialized default ×8 profile.
- `proof_artifacts__execution_proof_artifacts.snap` – golden proof envelope,
  transcript and Merkle bundle artefacts.
- `ser_primitives__digest_with_tag.snap` – digest serialization with
  domain-separation tags.
- `ser_structures__fri_proof_bytes.snap` – reference encoding of the FRI proof
  structure.
- `ser_structures__merkle_proof_bytes.snap` – reference encoding of a Merkle
  proof.
- `ser_structures__proof_bytes.snap` – serialized proof envelope bytes.
- `transcript_determinism__transcript_profile_x8.snap` – deterministic transcript
  challenge stream for the ×8 profile.

### Failure matrix fixtures (`tests/fail_matrix/snapshots`)

- `fail_matrix__composition__rejects_leaf_bytes_mismatch__indices.snap` –
  offending indices when composition leaves diverge.
- `fail_matrix__composition__rejects_leaf_bytes_mismatch__leaves.snap` – mutated
  composition leaves used in the rejection case.
- `fail_matrix__composition__rejects_leaf_bytes_mismatch__reason.snap` –
  rejection reason emitted by the verifier.
- `fail_matrix__fri__fri_rejects_fold_challenge_tampering_challenges.snap` –
  tampered fold challenges triggering a FRI failure.
- `fail_matrix__fri__fri_rejects_fold_challenge_tampering_error.snap` – verifier
  error emitted for the tampered fold challenge.
- `fail_matrix__fri__fri_rejects_fold_challenge_tampering_issue.snap` – issue
  report backing the fold-challenge tampering scenario.
- `fail_matrix__header__header_rejects_excessive_proof_size.snap` – proof-size
  overflow rejection.
- `fail_matrix__header__header_rejects_fri_offset_mismatch.snap` – mismatch
  between declared and actual FRI offsets.
- `fail_matrix__header__header_rejects_openings_offset_mismatch.snap` – mismatch
  between declared and actual openings offsets.
- `fail_matrix__header__header_rejects_param_digest_mismatch.snap` – parameter
  digest mismatch rejection.
- `fail_matrix__header__header_rejects_public_digest_mismatch.snap` – public
  digest mismatch rejection.
- `fail_matrix__header__header_rejects_telemetry_flag_mismatch.snap` – mismatch
  between telemetry flag and payload presence.
- `fail_matrix__header__header_rejects_telemetry_offset_mismatch.snap` – mismatch
  between declared and actual telemetry offsets.
- `fail_matrix__header__header_rejects_version_bump.snap` – version bump without
  ABI upgrade.
- `fail_matrix__indices__composition_rejects_duplicate_indices.snap` – duplicate
  indices for composition openings.
- `fail_matrix__indices__composition_rejects_mismatched_indices.snap` –
  mismatched composition indices.
- `fail_matrix__indices__composition_rejects_unsorted_indices.snap` – unsorted
  composition indices.
- `fail_matrix__indices__trace_rejects_duplicate_indices.snap` – duplicate trace
  indices.
- `fail_matrix__indices__trace_rejects_mismatched_indices.snap` – mismatched
  trace indices.
- `fail_matrix__indices__trace_rejects_unsorted_indices.snap` – unsorted trace
  indices.
- `fail_matrix__merkle__merkle_rejects_corrupted_trace_path.snap` – corrupted
  trace Merkle path rejection.
- `fail_matrix__merkle__merkle_rejects_header_root_mismatch.snap` – mismatch
  between header root and openings payload.
- `fail_matrix__merkle__merkle_rejects_inconsistent_trace_paths.snap` –
  inconsistent trace path rejection.
- `fail_matrix__ood__composition_ood_mismatch__tampered_out_of_domain.snap` –
  tampered composition out-of-domain point.
- `fail_matrix__ood__trace_ood_mismatch__tampered_out_of_domain.snap` – tampered
  trace out-of-domain point.
- `fail_matrix__snapshots__fail_matrix_fixture_artifacts.snap` – umbrella
  snapshot enumerating all fail-matrix artefacts.
- `fail_matrix__telemetry__telemetry_rejects_body_length_mismatch__frame.snap`
  – telemetry body length mismatch fixture.
- `fail_matrix__telemetry__telemetry_rejects_header_length_mismatch__frame.snap`
  – telemetry header length mismatch fixture.
- `fail_matrix__telemetry__telemetry_rejects_integrity_digest_mismatch__frame.snap`
  – telemetry integrity digest mismatch fixture.

## Change control

- Snapshots may only change alongside a `PROOF_VERSION` bump.
- Document the rationale in `CHANGELOG.md` whenever a snapshot update lands.
- Run `cargo test snapshot_profiles -- --exact` or `cargo insta review` to
  accept the new artefacts and ensure the CI snapshot guard passes.
- The `snapshot-guard` GitHub Action and the interop job reject pull requests
  that touch snapshots without the corresponding version bump and changelog
  entry.
