# Threat Model Addendum: Snapshot Lifecycle Controls

This addendum documents the controls that currently protect the snapshot lifecycle,
resumable state transfers, and admission policy changes. It also calls out the
security work that remains open so auditors can trace coverage gaps back to the
engineering backlog.

## Snapshot persistence controls
- **Disk-backed session metadata:** The runtime persists every active snapshot
  session to `<snapshot_dir>/snapshot_sessions.json`. The `SnapshotSessionStore`
  constructor creates the directory on demand, deserialises prior sessions, and
  re-emits them to disk after each update so crash recovery resumes from the last
  confirmed offsets.【F:rpp/runtime/node.rs†L1202-L1289】
- **Automatic restore on restart:** When the node boots, the snapshot provider
  rebuilds in-memory sessions from the stored records. Invalid records are
  discarded and removed from disk, limiting replay to verifiable manifests and
  peers that pass the stored integrity checks.【F:rpp/runtime/node.rs†L1292-L1356】
- **Inline manifest validation:** Before serving a restored session, the runtime
  re-decodes the advertised global state root from the plan and verifies it is a
  32-byte value. Malformed manifests fail the recovery path and never become
  eligible for streaming.【F:rpp/runtime/node.rs†L1368-L1379】

## Resume validation controls
- **Plan binding:** Resume requests must present the plan identifier that was
  originally persisted with the session. Mismatches are rejected before any data
  leaves disk.【F:rpp/runtime/node.rs†L1683-L1699】
- **Monotonic offsets:** The runtime clamps resume positions to the last confirmed
  chunk and light-client update. Requests that replay old data or skip ahead are
  rejected so the peer must re-synchronise from the trusted boundary.【F:rpp/runtime/node.rs†L1700-L1744】

## Admission audit logging controls
- **JSONL audit log:** The peerstore initialiser resolves or creates an
  `audit.jsonl` log beside the persisted access lists and opens it through the
  `AdmissionPolicyLog` helper. When present, every policy change is appended with
  the actor metadata, and failures bubble up so operators can detect gaps.【F:rpp/p2p/src/peerstore.rs†L525-L607】【F:rpp/p2p/src/peerstore.rs†L1088-L1119】
- **Immediate persistence of access changes:** Allowlist and blocklist updates are
  written back to disk after each change so subsequent restarts retain the same
  policy view that produced the audit entry.【F:rpp/p2p/src/peerstore.rs†L1121-L1138】

## Known gaps and future work
- **External snapshot verification:** Operators today rely on the runtime’s
  built-in validation path described above; there is no standalone
  `tools/firewood verify-manifest` utility yet. External, offline verification is
  tracked as follow-up work.
- **Dual approvals for policy changes:** The admission audit log records a single
  actor. Automated enforcement of dual signatures remains outstanding.
- **WORM export of audit logs:** Audit files are append-only locally, but the
  platform does not yet replicate them into immutable storage.

## Follow-ups
- [ENG-921 — Snapshot replay hardening](../status/weekly.md#snapshot-replay-hardening-eng-921)
- [ENG-923 — Tier policy persistence](../status/weekly.md#tier-policy-persistence-eng-923)
- [ENG-924 — Audit trail reconciliation](../status/weekly.md#audit-trail-reconciliation-eng-924)
