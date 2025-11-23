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
   checksum using the manifest’s `checksum_algorithm` (default: `sha256`). The
   runtime refuses to serve a snapshot when any manifest entry is stale or
   tampered, returning a structured error instead of streaming corrupted data.
4. The manifest format version must match the runtime expectation (currently
   `version=1`). Validators refuse to serve manifests with any other version
   and surface the mismatch instead of streaming chunks. The `rpp-node
   validator snapshot verify` command and `snapshot-verify` tool abort with a
   fatal error when the version field is missing or bumped, making mismatches
   obvious during automation.

The validator runtime refuses to serve snapshots when the `.sig` companion is
missing or malformed. Operators must publish both files together, keep their
paths stable across restarts, and rotate them atomically so consumers never see
an unsigned or stale manifest.

### Tamper detection and alerting

State-sync streams abort immediately when a previously valid session encounters
a tampered manifest or chunk mid-stream. The light client surfaces a
`PipelineError::SnapshotVerification` containing the specific mismatch (for
example, a `commitment mismatch` string) so operators can distinguish tampering
from transient I/O failures. Every rejection increments
`rpp_node_pipeline_state_sync_tamper_total{reason="snapshot_verification"}`,
and the `StateSyncTamperDetected` alert in
`docs/observability/alerts/root_integrity.yaml` fires when the counter increases
within five minutes. Scraping this metric provides a single place to confirm
tamper events even when clients abort before all chunks are downloaded.

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

Manifests include a `checksum_algorithm` header and per-segment `checksum`
entries so providers can opt into stronger digests like `blake2b` while keeping
`sha256` as the default. The validator config key
`snapshot_checksum_algorithm` selects the fallback when older manifests omit
the field, and the `validator snapshot verify`/`snapshot-verify`
`--checksum-algorithm` flag provides the equivalent override for CLI audits.

### Manifest versions and upgrades

Snapshots currently use manifest format version `1`. Providers and consumers
must keep this value in sync with their binaries: state sync servers emit
`ManifestViolation` errors when the on-disk version differs, and consumers abort
verification runs with a fatal "version mismatch" message. When introducing a
new manifest format, publish the updated manifest and signature only after
rolling out binaries that understand the new version. Avoid serving mixed
versions from the same directory to prevent clients from encountering fatal
errors mid-download.

Each invocation records `snapshot_verify_results_total` with a `result`
(`success`/`failure`) and `error` label (`none`, `signature_invalid`,
`chunk_mismatch`, `fatal`). Operators scraping Prometheus or OTLP exporters can
track how many manifests succeeded during a build and which error class is
dominating failures. The compliance alert bundle surfaces warning/critical
conditions when more than 10%/25% of runs fail across at least three attempts in
30 minutes.

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

Snapshot RPC responses and pollable stream statuses surface a `download_error`
code when the runtime aborts a stream:

* `network` – the peer disconnected, requests timed out, or the transport could
  not encode a message. Retry with backoff; consider shrinking
  `max_concurrent_downloads` on lossy links.
* `checksum` – a chunk or manifest failed validation. Restart the download from
  scratch and verify the provider’s manifest and signatures before retrying.
* `authentication` – RPC authentication failed. Refresh the bearer token or
  client certificate and resend the request.
* `resume_mismatch` – the provided resume marker does not match the persisted
  plan or snapshot root. Query the latest session status and retry using the
  returned `plan_id` to avoid rewinding or skipping chunks.

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

### Adaptive chunk sizing

Snapshot streams adapt chunk sizes to the observed bandwidth-delay product so
slow links avoid retransmitting oversized payloads while fast links keep the
pipe full. Providers advertise `snapshot_sizing.{min_chunk_size,max_chunk_size}`
and the default chunk size through the plan response; consumers feed request/response
RTT and chunk byte counts into an adaptive strategy that grows or shrinks the
next request within the advertised bounds. Start requests can override the
initial chunk size to account for known constraints, but the runtime will clamp
it to the configured limits.

Operators can tune the caps in `node.toml` to match their network profile:

* `snapshot_sizing.default_chunk_size` – starting point for the adaptive sizing
  strategy (must fall between `min_chunk_size` and `max_chunk_size`).
* `snapshot_sizing.min_chunk_size` – smallest chunk the provider will serve; use
  lower values for high-latency or metered links.
* `snapshot_sizing.max_chunk_size` – upper bound for chunk requests; increase on
  LAN/IX environments to reduce request overhead.

If downloads stall or oscillate between chunk sizes, tighten the min/max window
and check provider telemetry (`snapshot_bytes_sent_total` and
`snapshot_stream_lag_seconds`) to confirm progress. Consumers expose the
negotiated chunk size and bounds through the snapshot status RPC, which helps
debug mismatches between requested and served sizes.

## Parallel snapshot downloads

Snapshot streams can download multiple chunks in parallel. The CLI flag
`--max-concurrent-downloads` (also available via
`RPP_SNAPSHOT_MAX_CONCURRENT_DOWNLOADS`) controls the client-side parallelism
and defaults to `snapshot_download.max_concurrent_chunk_downloads` in
`node.toml` (default: `4`). Providers may advertise a lower
`max_concurrent_requests` in the plan response; the runtime clamps client
requests to whichever limit is smaller to avoid overwhelming peers.

The `snapshot_stream_parallel_benchmark_reports_throughput` test exercises
concurrency levels 1, 2, and 4 with synthetic payloads and prints lines shaped
like `snapshot_parallel_metrics concurrency=4 throughput_bps=...` so operators
can capture throughput and lag under different profiles. Use those numbers to
pick baselines:

* WAN/VPN links: start with `max_concurrent_downloads=1` or `2` to reduce tail
  latency spikes and backpressure when round-trip times dominate. Combine with
  the retry flags (`--snapshot-retry-attempts` and
  `--snapshot-retry-backoff-ms`) to smooth out transient packet loss without
  inflating the in-flight window.
* LAN/IX fabrics: `3-4` parallel chunk requests usually saturate the local
  connection without triggering provider throttling. If the benchmark logs show
  the tail gap growing, lower the chunk size bounds or parallelism until the
  reported `avg_chunk_gap_ms` stabilises.

Higher parallelism interacts with chunk sizing: large chunks with high
parallelism can overwhelm provider I/O queues, while tiny chunks at high
parallelism can exacerbate retry storms. Keep `min_chunk_size`/`max_chunk_size`
tight for WAN paths and pair higher parallelism with larger chunk caps on fast
links. When a plan advertises `max_concurrent_requests`, treat it as a hard cap
and avoid overriding it in the CLI or config; mismatches will otherwise cause
retries and extend `tail_gap_ms` in the benchmark output.

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
