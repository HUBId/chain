# Timetoke Snapshot Signatures

Timetoke snapshot manifests are signed with the Ed25519 key configured via
`timetoke_snapshot_key_path` on the node configuration. During snapshot
publication the runtime canonicalises the manifest JSON bytes, produces a
signature with `ed25519-dalek`, and stores the base64-encoded result alongside
the payload in the in-memory `SnapshotStore`.

When snapshots are persisted to disk (for example by services writing
`*.json` manifests), a `*.json.sig` companion file must be written containing
the detached signature as plain base64. Consumers can verify manifests by
base64-decoding the signature and checking it against the canonical JSON bytes
with the corresponding `VerifyingKey`.

State sync remains backwards compatible with legacy manifests that lack a
signature. The loader logs a single warning per snapshot root and serves the
unsigned payload; once all manifests ship `.sig` companions this fallback will
be removed.
