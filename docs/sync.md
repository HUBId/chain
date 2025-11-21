# State sync snapshot workflow

State sync relies on pruning snapshots exported by validators. Every snapshot
payload is hashed (`blake3`) and streamed in fixed-size chunks while light client
updates advance the head. Downstream consumers reconstruct the manifest payload
from disk before chunks are served, so the runtime enforces two invariants:

1. The payload on disk must hash to the session root; any mismatch aborts the
   request and surfaces `SnapshotRootMismatch` to the caller.
2. A detached Ed25519 signature (`<payload>.sig`) must exist alongside the
   payload. The signature is expected to be prefixed with the signing key
   version (for example, `1:<base64>` with the current key version `1`) and
   base64 encoded without trailing whitespace; invalid encoding or a stale key
   version is treated as corruption.
3. Every chunk referenced in `manifest/chunks.json` must exist under
   `<snapshot_dir>/chunks`, match the recorded size, and hash to the recorded
   `sha256`. The runtime refuses to serve a snapshot when any manifest entry is
   stale or tampered, returning a structured error instead of streaming
   corrupted data.

The validator runtime refuses to serve snapshots when the `.sig` companion is
missing or malformed. Operators must publish both files together, keep their
paths stable across restarts, and rotate them atomically so consumers never see
an unsigned or stale manifest.

## Publishing new snapshots

* Write the manifest payload to disk (canonical JSON) and compute its Blake3
  digest. This digest becomes the session root that clients use to resume.
* Sign the raw manifest bytes with the configured Timetoke snapshot signing key
  (`timetoke_snapshot_key_path`). Encode the signature as base64, prefix it with
  the signing key version from the key file (for example `1:<base64>`), trim
  it, and write it to `<manifest>.sig`.
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
pipelines and post-incident audits. Rotate signing keys by bumping the
`version` field in `timetoke_snapshot_key_path`, regenerating the signature with
the new key, and republishing the `{manifest, manifest.sig}` pair; the runtime
rejects snapshots signed with older key versions so stale signatures cannot be
served once the version changes.

## Snapshot download retries

The `rpp-node validator snapshot` commands use an HTTP client to start, poll,
resume, and cancel snapshot sessions through the validator RPC. Transient RPC
errors are retried with an exponential backoff. The retry parameters can be
controlled per invocation:

* `--snapshot-retry-attempts` (default: `3`) – total request attempts before
  surfacing an error to the caller.
* `--snapshot-retry-backoff-ms` (default: `200`) – the initial backoff delay in
  milliseconds. Each retry doubles the delay until attempts are exhausted.

Tune these flags when scripting against unstable links so transient failures do
not abort snapshot downloads, while still surfacing permanent errors promptly.

### Resume semantics

Snapshot downloads can be resumed without re-transferring verified chunks. The
`POST /p2p/snapshots` RPC accepts a `resume` payload containing the persisted
`session` identifier and the last known `plan_id` advertised by the provider
(`plan_id` falls back to the snapshot root when the plan has not rotated). When
`resume` is present the server replays a resume request against the snapshot
provider using the stored chunk and update indices; if the supplied `plan_id`
differs from the persisted session metadata the call fails with a 500 and an
error string containing "plan id" so clients can refresh the session status
before retrying.

After sending the resume request, poll `GET /p2p/snapshots/<session>` until
`verified=true` to confirm all chunks and light-client updates have been fetched
and re-verified. Consumers should restart the download with the same session
and plan identifier after restarts or transport interruptions; the runtime
maintains the offsets on disk and will reject regressed or skipped ranges while
continuing from the next expected chunk.

## Snapshot download authentication

Snapshot download and status endpoints reuse the validator RPC surface, so the
same authentication settings apply. When operators set
`network.rpc.require_auth = true` the runtime refuses to start unless a matching
`network.rpc.auth_token` is configured, ensuring that download endpoints are
never exposed without credentials. Deployments that need mutual TLS can also
enable `network.tls.require_client_auth` and provide the CA bundle under
`network.tls.client_ca`.

Clients can supply the bearer token through the `RPP_SNAPSHOT_AUTH_TOKEN`
environment variable or the `--auth-token` flag. For TLS-protected endpoints,
use `--snapshot-ca-certificate`, `--snapshot-client-certificate`, and
`--snapshot-client-key` (or their `RPP_SNAPSHOT_*` environment variables) to
trust custom roots and present a client identity.
