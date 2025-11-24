# Snapshot streaming protocol

This guide documents the libp2p snapshot request/response protocol, how flow
control and resume markers work, and how the runtime and RPC layers expose the
feature to operators.

## Wire protocol

Snapshot data is exchanged over the `/rpp/snapshots/1.0.0` request/response
protocol. Each session is keyed by a `SnapshotSessionId` and transports several
artefact types (`plan`, `chunk`, `light_client_update`, `resume`, `ack`,
`error`).【F:rpp/p2p/src/behaviour/snapshots.rs†L36-L158】 Plan/Resume requests
can optionally advertise a preferred `chunk_size` together with capability
bounds so providers can tailor the payload size; plan responses mirror the
offered sizing when available.【F:rpp/p2p/src/behaviour/snapshots.rs†L91-L139】 Providers implement the
`SnapshotProvider` trait to serve plans, chunks, and recursive proof updates, to
surface resume offsets, and to record acknowledgements from the consumer.【F:rpp/p2p/src/behaviour/snapshots.rs†L141-L175】

Requests and responses are encoded as JSON and carried in bounded payloads by
the libp2p request/response codec.【F:rpp/p2p/src/behaviour/snapshots.rs†L362-L401】
Consumers first request the plan, then stream chunk data and light client
updates, and can resume or cancel a session via dedicated messages.【F:rpp/p2p/src/behaviour/snapshots.rs†L454-L571】 Providers reply with the
requested artefact or an error payload and mirror acknowledgements back to the
caller.【F:rpp/p2p/src/behaviour/snapshots.rs†L638-L861】

## Flow control and resume markers

The behaviour keeps per-session state (peer, next chunk/update indices, and the
currently in-flight request). A session never has more than one outstanding
request; if an application calls into the behaviour while a request is still
pending, the helper returns `None` to signal backpressure.【F:rpp/p2p/src/behaviour/snapshots.rs†L404-L543】 Successful responses update the
`next_chunk_index`/`next_update_index`, so the consumer can resume from the
correct offsets after reconnecting.【F:rpp/p2p/src/behaviour/snapshots.rs†L895-L956】 When a consumer issues a `Resume` request the
provider translates it into a `SnapshotsResponse::Resume` that advertises the
next chunk/update indices that should be requested.【F:rpp/p2p/src/behaviour/snapshots.rs†L780-L957】

The runtime snapshot provider rejects resumes that fall behind the latest
persisted acknowledgement or attempt to skip ahead of the advertised totals.
`resume_session` bounds the requested chunk and update indices by the plan
totals sourced from the persisted session metadata and the most recent
confirmed offsets; regressed indices raise
`PipelineError::SnapshotVerification` errors and requests that exceed the
advertised totals now surface `PipelineError::ResumeBoundsExceeded`, both of
which propagate back through the runtime and RPC layers.【F:rpp/runtime/node.rs†L1680-L1752】【F:rpp/p2p/src/behaviour/snapshots.rs†L695-L733】 The session metadata
also persists the snapshot `plan_id`, and consumers must echo it when resuming.
Mismatches are rejected with a clear verification error—`"plan id … does not
match persisted plan …"`—that bubbles up through the RPC surface so operators
can see when a provider has rotated its snapshot.【F:rpp/runtime/node.rs†L1514-L1552】【F:rpp/rpc/src/routes/p2p.rs†L23-L118】
Integration tests cover both the HTTP and runtime handle surfaces to guard the
behaviour.【F:tests/network/snapshots_resume.rs†L1-L310】

### Resume telemetry and monitoring

The snapshots behaviour exports resume-specific gauges to track checksum validation as soon as a provider accepts a resume
request. `snapshot_resume_validated_bytes` and `snapshot_resume_progress_ratio` report the approximate bytes validated and the
fraction of the advertised plan covered by the resume response, while
`snapshot_resume_checksum_state{state="mismatch"}` flips to 1 when a checksum error is reported during resume
handshakes.【F:rpp/p2p/src/behaviour/snapshots.rs†L1002-L1088】【F:rpp/p2p/src/behaviour/snapshots.rs†L2807-L2898】 The snapshot
resilience dashboard includes panels for these gauges alongside the existing resume success charts so operators can spot stalls
or mismatches without digging through logs.【F:docs/dashboards/snapshot_resilience.json†L180-L272】 Prometheus alerts fire when
checksum progress stops advancing or when the checksum state reports a mismatch for more than a few minutes.【F:telemetry/prometheus/cache-rules.yaml†L100-L148】 Assess the most recent progress ratio and checksum state before
retrying a resume to avoid duplicating corrupt data.

### Provider concurrency limits

Snapshot providers can cap inbound session concurrency via
`p2p.snapshot_max_inbound_sessions`. The behaviour checks the configured limit
before opening a new session; when saturated it returns an error response and the
runtime marks the consumer session as failed with the `network` error code.
Capacity caps help prevent slow or malicious consumers from starving the
provider; start with `1`–`2` concurrent sessions unless the host has headroom for
multiple exports.【F:rpp/runtime/config.rs†L1028-L1097】【F:rpp/p2p/src/behaviour/snapshots.rs†L2218-L2262】【F:rpp/runtime/node_runtime/node.rs†L2065-L2123】 Prometheus metrics expose the configured cap via
`snapshot_concurrency_limit{source="configured"}` and count saturated responses
via `snapshot_message_bytes_total{direction="inbound",flow="sent",kind="error"}`;
alert on a rising error rate to trigger backoff/retry policies before consumers
pile up.


Acknowledge messages let consumers confirm ingestion of specific artefacts. The
provider receives `Ack` requests, persists the acknowledgement, and echoes a
matching response; outbound errors trigger `SnapshotProtocolError::Outbound`
events so higher layers can retry or fail the session.【F:rpp/p2p/src/behaviour/snapshots.rs†L813-L840】【F:rpp/p2p/src/behaviour/snapshots.rs†L578-L633】

## Chunk sizing defaults and caps

Snapshot providers advertise sizing hints so consumers can negotiate chunk
sizes that fit their bandwidth and latency envelope. Tune the defaults via the
`snapshot_sizing` section in `node.toml` (see [state sync tuning](../sync.md#adaptive-chunk-sizing)
for operational guidance):

- `snapshot_sizing.default_chunk_size` controls the chunk size used when
  generating state sync plans and when no consumer preference is supplied
  (default: 16).
- `snapshot_sizing.min_chunk_size` and `snapshot_sizing.max_chunk_size` bound the
  adaptive sizing strategy advertised to peers, ensuring negotiated sizes stay
  within operator-defined caps (defaults: 16/16).

Values must be non-zero and satisfy `min <= default <= max`; invalid settings
are rejected during configuration validation.【F:rpp/runtime/config.rs†L1703-L1765】【F:rpp/runtime/config.rs†L2326-L2358】 The runtime snapshot provider
uses these values both to build plans and to surface capability bounds to the
network behaviour.【F:rpp/runtime/node.rs†L1558-L1606】【F:rpp/runtime/node.rs†L2068-L2105】

## Runtime session manager

The node runtime wraps the behaviour in a session manager that tracks progress
and exposes it via `SnapshotStreamStatus`. Every status entry records the latest
chunk/update indices, the height of the most recent verified light-client
update, and whether the session has completed verification or encountered an
error.【F:rpp/runtime/node_runtime/node.rs†L375-L399】【F:rpp/runtime/node_runtime/node.rs†L1119-L1163】 Starting or resuming a
stream resets these fields and clears previous errors before issuing the
underlying network command.【F:rpp/runtime/node_runtime/node.rs†L1223-L1276】 Session metadata (plan
root, peer ID, totals, and the last confirmed chunk/update) is durably persisted
under the node’s snapshot directory and reloaded during bootstrap so restart
requests resume from the correct offsets.【F:rpp/runtime/node.rs†L1160-L1305】 Updates to plans,
chunks, light-client updates, and acknowledgements immediately refresh the
on-disk record, and resume requests that advertise chunk or update indices
outside the persisted totals are rejected with a snapshot verification
error.【F:rpp/runtime/node.rs†L1323-L1509】【F:rpp/runtime/node.rs†L1479-L1504】

Failures propagate through `snapshot_stream_failure`, which marks the session as
failed and emits `NodeEvent::SnapshotStreamFailed`; consumers can listen for
that event or poll the runtime handle for details.【F:rpp/runtime/node_runtime/node.rs†L1145-L1163】 Cancelling a session removes the
tracked status entirely.【F:rpp/runtime/node_runtime/node.rs†L1279-L1288】

## Light client verification

`LightClientSync` consumes the streamed plan, chunks, and recursive proof
updates. It validates every payload against the advertised commitments, enforces
chunk ordering, verifies recursive proofs, and only emits a new head once the
chain of updates is complete.【F:rpp/p2p/src/pipeline.rs†L1311-L1408】【F:rpp/p2p/src/pipeline.rs†L1409-L1497】 The runtime subscribes to
these heads so snapshot consumers can confirm when the state sync has produced a
verified checkpoint.【F:rpp/runtime/node_runtime/node.rs†L1005-L1015】 The end-to-end behaviour—including RPC wiring, network
flow control, persistence, and the light client verifier—is exercised by
`tests/network/snapshots.rs` to prevent regressions.【F:tests/network/snapshots.rs†L1-L361】

## HTTP control plane

Operators trigger streaming through the RPC service:

```bash
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $RPP_RPC_TOKEN" \
  -d '{"peer":"<provider-peer-id>","chunk_size":32768}' \
  http://<consumer-host>:<port>/p2p/snapshots
```

The POST request allocates or resumes a session (include
`{"resume":{"session":<id>,"plan_id":"<plan-id>"}}` to reuse an existing
stream) and returns the
initial `SnapshotStreamStatus`. Poll status updates via:

```bash
curl -sS \
  -H "Authorization: Bearer $RPP_RPC_TOKEN" \
  http://<consumer-host>:<port>/p2p/snapshots/<session>
```

The `$RPP_RPC_TOKEN` environment variable should contain the bearer token
issued by the RPC service during deployment or operator onboarding.

> **Note:** Authenticated deployments must include the bearer token header with
> every snapshot control-plane request to avoid `401 Unauthorized` responses.

The handler parses the peer ID, synthesises a new session ID when one is not
provided, forwards the command to the runtime, and serialises the status back to
the caller.【F:rpp/rpc/src/routes/p2p.rs†L16-L102】 Status responses mirror the runtime fields so operators can see the
latest chunk/update indices, the persisted `plan_id`, verification result, or
error message.【F:rpp/runtime/node_runtime/node.rs†L372-L413】【F:rpp/rpc/src/routes/p2p.rs†L36-L78】

## Failure handling

Provider errors or decode failures surface as `SnapshotsResponse::Error`, which
are converted into `SnapshotProtocolError::Provider`/`Remote` events for the
runtime to inspect.【F:rpp/p2p/src/behaviour/snapshots.rs†L638-L859】 The runtime records the error string in the corresponding
`SnapshotStreamStatus` and marks the session as unverified.【F:rpp/runtime/node_runtime/node.rs†L1145-L1156】 RPC clients receive
`404` responses if they query an unknown session, and transport failures convert
to HTTP error codes via `snapshot_runtime_error_to_http`.【F:rpp/rpc/src/routes/p2p.rs†L70-L102】【F:rpp/rpc/api.rs†L227-L270】


## Background chunk validation

Nodes continuously audit the snapshot chunks they keep on disk. The
`SnapshotValidator` service reads `<snapshot_dir>/manifest/chunks.json`,
recomputes the SHA-256 digests for every entry in `<snapshot_dir>/chunks`, and
reports discrepancies as `snapshot_chunk_checksum_failures_total{kind="…"}`
increments alongside structured warnings from the `snapshot_validator`
target.【F:rpp/node/src/services/snapshot_validator.rs†L1-L205】【F:rpp/node/src/telemetry/snapshots.rs†L1-L33】 The cadence defaults to five
minutes and can be tuned through `snapshot_validator.cadence_secs` in
`node.toml`.【F:rpp/runtime/config.rs†L1256-L1761】 Keep manifest and
chunk directories in sync whenever snapshots rotate so the validator catches
corruption immediately after tampering or partial deployments.

The runtime refuses to serve snapshots unless the payload has a companion
`<file>.sig` containing a base64-encoded Ed25519 signature. Missing or invalid
signatures surface as I/O errors and prevent state sync from streaming chunks,
so always rotate manifest and signature files together.

## Offline manifest verification

Release bundles and nightly audits ship the pruning snapshot manifest
(`manifest/chunks.json`) together with a detached Ed25519 signature. The
`snapshot-verify` CLI validates both the signature and every chunk checksum
before the artifacts are published. Provide the manifest, signature, chunk
directory, and the hex/base64 encoded verifying key:

```bash
cargo run --locked --package snapshot-verify -- \
  --manifest dist/artifacts/x86_64-unknown-linux-gnu/snapshots/manifest/chunks.json \
  --signature dist/artifacts/x86_64-unknown-linux-gnu/snapshots/manifest/chunks.json.sig \
  --public-key ~/keys/snapshot-manifest.hex \
  --chunk-root dist/artifacts/x86_64-unknown-linux-gnu/snapshots/chunks \
  --output dist/artifacts/x86_64-unknown-linux-gnu/snapshots/manifest/chunks-verify.json
```

The tool emits a machine-readable JSON report summarising the signature check,
per-segment results, and aggregate counters. Exit codes indicate the failure
mode:

- `0` – signature and all chunk hashes match the manifest
- `2` – signature verification failed
- `3` – at least one segment is missing, has a size mismatch, or fails the
  checksum comparison
- `1` – I/O or decode error prevented verification from running

The release and nightly workflows persist the JSON report alongside the other
artifacts so auditors can cross-reference CI output with manual runs.【F:.github/workflows/release.yml†L122-L155】【F:.github/workflows/nightly.yml†L20-L118】 Nightly
verification runners must stage the chunk directory before invoking the CLI;
set `SNAPSHOT_CHUNK_ARCHIVE_URL` to a tarball/zip that mirrors the manifest’s
`chunks/` layout (optionally combine it with `SNAPSHOT_CHUNK_ROOT_SUBDIR` when
the archive nests the directory) and the workflow unpacks the archive into a
temporary workspace before the verification step runs.【F:.github/workflows/nightly.yml†L60-L118】
