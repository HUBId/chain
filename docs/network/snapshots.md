# Snapshot streaming protocol

This guide documents the libp2p snapshot request/response protocol, how flow
control and resume markers work, and how the runtime and RPC layers expose the
feature to operators.

## Wire protocol

Snapshot data is exchanged over the `/rpp/snapshots/1.0.0` request/response
protocol. Each session is keyed by a `SnapshotSessionId` and transports several
artefact types (`plan`, `chunk`, `light_client_update`, `resume`, `ack`,
`error`).【F:rpp/p2p/src/behaviour/snapshots.rs†L36-L139】 Providers implement the
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
totals and the most recent confirmed offsets; regressed indices raise
`PipelineError::SnapshotVerification` errors that propagate back through the
runtime and RPC layers.【F:rpp/runtime/node.rs†L1670-L1724】【F:rpp/rpc/api.rs†L2958-L2966】 Operators invoking
`POST /p2p/snapshots` with a `resume` marker receive the same error payload, so
resuming with stale offsets produces a `500` response describing the offending
chunk or update. Integration tests cover both the HTTP and runtime handle
surfaces to guard the behaviour.【F:tests/network/snapshots_resume.rs†L1-L310】

Acknowledge messages let consumers confirm ingestion of specific artefacts. The
provider receives `Ack` requests, persists the acknowledgement, and echoes a
matching response; outbound errors trigger `SnapshotProtocolError::Outbound`
events so higher layers can retry or fail the session.【F:rpp/p2p/src/behaviour/snapshots.rs†L813-L840】【F:rpp/p2p/src/behaviour/snapshots.rs†L578-L633】

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
`{"resume":{"session":<id>}}` to reuse an existing stream) and returns the
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
latest chunk/update indices, verification result, or error message.

## Failure handling

Provider errors or decode failures surface as `SnapshotsResponse::Error`, which
are converted into `SnapshotProtocolError::Provider`/`Remote` events for the
runtime to inspect.【F:rpp/p2p/src/behaviour/snapshots.rs†L638-L859】 The runtime records the error string in the corresponding
`SnapshotStreamStatus` and marks the session as unverified.【F:rpp/runtime/node_runtime/node.rs†L1145-L1156】 RPC clients receive
`404` responses if they query an unknown session, and transport failures convert
to HTTP error codes via `snapshot_runtime_error_to_http`.【F:rpp/rpc/src/routes/p2p.rs†L70-L102】【F:rpp/rpc/api.rs†L227-L270】

