# rpp-stark v1.0.0-beta Release Notes

## Overview
First beta of the STWO-compatible `rpp-stark` proof system targeting production readiness while keeping the proof ABI frozen.

## Highlights
- Proof envelope and verifier fully cover Header → Transcript → Queries → Merkle → FRI → Composition → Report.
- Fail-Matrix coverage across the proving pipeline.
- Deterministic Golden Vectors for regression detection.
- Snapshot-Guard ensures CI enforces PROOF_VERSION discipline for serialized artifacts.
- Interop CI validates the STWO Golden Vector set on every change.

## Compatibility
- Minimum supported Rust version (MSRV): 1.79.
- Builds and tests run on stable toolchains only; no nightly features required.
- Proof ABI remains stable at `PROOF_VERSION = 1` for this beta.

## Known Limitations
- Additional execution profiles and backend integrations are planned for upcoming betas.
- Parameter snapshot automation beyond proof artifacts will follow in future releases.

## Upgrade Notes
- Respect the existing `PROOF_VERSION` policy: bump the constant and document the change if the serialized proof layout evolves.
- Review snapshot updates guarded by CI to ensure any serialization changes are intentional and documented.
- Downstream consumers should verify their snapshot baselines against the Golden Vectors before deployment.
