# State sync snapshot workflow

State sync relies on pruning snapshots exported by validators. Every snapshot
payload is hashed (`blake3`) and streamed in fixed-size chunks while light client
updates advance the head. Downstream consumers reconstruct the manifest payload
from disk before chunks are served, so the runtime enforces two invariants:

1. The payload on disk must hash to the session root; any mismatch aborts the
   request and surfaces `SnapshotRootMismatch` to the caller.
2. A detached Ed25519 signature (`<payload>.sig`) must exist alongside the
   payload. The signature is expected to be base64 encoded without trailing
   whitespace; invalid encoding is treated as corruption.

The validator runtime refuses to serve snapshots when the `.sig` companion is
missing or malformed. Operators must publish both files together, keep their
paths stable across restarts, and rotate them atomically so consumers never see
an unsigned or stale manifest.

## Publishing new snapshots

* Write the manifest payload to disk (canonical JSON) and compute its Blake3
  digest. This digest becomes the session root that clients use to resume.
* Sign the raw manifest bytes with the configured Timetoke snapshot signing key
  (`timetoke_snapshot_key_path`). Encode the signature as base64, trim it, and
  write it to `<manifest>.sig`.
* Atomically rotate the pair—either by writing to a staging directory and
  renaming, or by writing both files under a temporary name before swapping the
  parent directory. Never publish a payload without its signature.

The tooling under `cargo xtask snapshot-verifier` and the release build scripts
assume signatures are present; they fail when the detached file is missing or
fails verification. This provides a safety net for operator automation.

## Verifying snapshots

To audit a published snapshot:

```bash
cargo run --locked --package snapshot-verify -- \
  --manifest /var/lib/rpp-node/snapshots/manifest/chunks.json \
  --signature /var/lib/rpp-node/snapshots/manifest/chunks.json.sig \
  --public-key ~/keys/timetoke_snapshot.hex \
  --chunk-root /var/lib/rpp-node/snapshots/chunks
```

The verifier reports signature validity, per-chunk checksum status, and exits
non-zero if any mismatch is detected. Incorporate this command into deployment
pipelines and post-incident audits.
