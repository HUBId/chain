# Changelog

All notable changes to `rpp-stark` are documented in this file. The structure follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate adheres to Semantic Versioning. Proof serialization stability is tracked separately via the `PROOF_VERSION` constant.

## Versioning policy

### Proof ABI (`PROOF_VERSION`)

- Bump `PROOF_VERSION` whenever any byte-level aspect of the proof ABI changes (envelope header, openings, transcript labels, Merkle bundle encoding, telemetry).
- Mirror the new value in every module that re-exports the constant (e.g. `src/proof/types.rs`, `src/merkle/proof.rs`, `src/config/mod.rs`) so verifiers and tooling agree on the proof layout.
- Regenerate and inspect the deterministic fixtures after the bump; include the snapshot diffs and a CHANGELOG entry that summarises the ABI impact.

### Snapshot maintenance

- `tests/snapshots/proof_artifacts__execution_proof_artifacts.snap` is the canonical fixture for the proof envelope and Merkle bundle layout.
- Regenerate snapshots after intentional ABI changes by running `cargo test -p rpp-stark -- --nocapture` followed by `cargo insta review` and commit the approved diffs.
- If snapshots change without bumping `PROOF_VERSION`, halt the review and decide whether the change is a bug or requires an ABI bump.

### ABI-Änderungspolitik

- Jede Änderung am Proof-ABI (Feldreihenfolge, Endianness, Tags, Längenfelder,
  Domain-Tags, Hashfamilie, Public-Inputs-Encoding) erfordert `PROOF_VERSION++`
  inklusive Snapshot-Update und kurzer Beschreibung des Effekts.

### Snapshots-Änderungen

- Snapshots dürfen nur angepasst werden, wenn `PROOF_VERSION++` im selben Pull
  Request erfolgt und der Grund im Changelog dokumentiert ist.

### Golden-Vector

- Der Interop-Vektor unter `vectors/stwo/mini` fungiert als Golden-Quelle.
  Änderungen sind nur nach obiger ABI-Policy zulässig.

## [Unreleased]

No unreleased changes.

## [1.0.0-beta] - 2025-10-12

- Added: Proof-Envelope & Verifier (Header→Transcript→Queries→Merkle→FRI→Composition→Report)
- Added: Fail-Matrix & Golden Vectors
- Added: Snapshot-Guard (CI) & Interop-Golden-Vector-Check
- Changed: MSRV 1.79
- Note: ABI frozen at PROOF_VERSION = 1 (no ABI change in this release)

### ABI

- Proof envelope, transcript, and Merkle bundle serialization are frozen at `PROOF_VERSION = 1`; deterministic snapshots gate regressions in `tests/snapshots/proof_artifacts__execution_proof_artifacts.snap`.

### Added

- Optional `backend-rpp-stark` feature exposing chain-integration adapters for felts, digests and deterministic hashing, including proof-size limit mapping helpers and STWO fixture tests.
- (2025-10-12) Add STWO interop documentation (no ABI change). ABI-Änderungen erfordern PROOF_VERSION++ und Snapshot-Update.
- (2025-10-12) Clippy clean, Snapshot & Changelog policies added (no ABI change).

### Changed

- (2025-10-12) Bump MSRV to 1.79 (no API changes).
- Raised the minimum supported Rust version (MSRV) and CI toolchain to 1.79 to align with deterministic builds (see `RELEASE_NOTES.md`).

### Known gaps / follow-up

- Parameter snapshot guard ("Param-Snapshot-Gate") is still manual; introduce a CI job that rejects changes to parameter digests without a documented justification.
- Re-evaluate the MSRV 1.79 bump for downstream consumers before tagging the next release; include compatibility notes once a release candidate is prepared.
