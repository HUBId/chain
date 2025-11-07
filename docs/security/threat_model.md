# Threat Model Addendum: Snapshot Lifecycle Controls

This addendum expands the platform threat model with controls that defend the
snapshot lifecycle, resumable state transfers, and auditability of privileged
operations.

## Snapshot Replay Mitigations
- **Replay-resistant manifests:** Snapshots are signed with rotation-aware
  manifests; validators verify the epoch seal, height monotonicity, and the
  hash chain across differential chunks before applying state.
- **Wormhole detection:** State-sync peers maintain rolling digests of accepted
  snapshots. Any replayed height hash mismatch is quarantined and reported via
  the consensus tamper channel, blocking propagation.
- **Out-of-band verification:** Operators can verify snapshot bundles against
  the published manifest ledger using `tools/firewood verify-manifest`, closing
  the replay window created by offline bootstraps.

## Resume Validation Controls
- **Checkpoint attestation:** A resumable download must present the signed
  attestation from its originating validator set. Missing or stale attestations
  trigger a restart with a fresh manifest pull.
- **Partial chunk hashing:** The resume handler re-hashes byte ranges before
  resuming transfer and compares them against the manifest Merkle proofs to
  ensure no tampering occurred while the transfer was paused.
- **Rate-limited retries:** Automated retries back off exponentially and log
  structured events to prevent brute-force probing of the resume interface.

## Tier Policy Persistence
- **Config checkpointing:** Tier admission policies (witness ACLs, gossip caps,
  and rate controls) are persisted to an append-only Firewood log. Nodes replay
  the log on boot before accepting inbound tier changes.
- **Version-gated updates:** Policy updates are wrapped in consensus-approved
  payloads that include schema versions. Mismatched versions are rejected,
  forcing operators to reconcile drift explicitly.
- **Dual control:** High-sensitivity policy changes require dual signatures
  (operations + security). Automation enforces that both approvals are present
  before the change log entry is committed.

## Audit Trail Hardening
- **Structured event logging:** Snapshot ingestion, resume attempts, and policy
  mutations emit structured events into the SIEM pipeline with correlation IDs
  that cover the entire lifecycle of the operation.
- **Immutable storage:** Audit events are exported into the retention-tier
  object store with WORM (write once, read many) controls enabled, providing a
  tamper-evident record for forensic review.
- **Periodic reconciliation:** A scheduled job compares local audit buffers
  with the retention store and raises alerts if entries are missing or have
  diverged, ensuring continuity of evidence.
