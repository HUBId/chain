# State Sync Verification and Telemetry

State sync snapshots ship with pruning receipts, recursive proofs, and light
client updates. The verification pipeline stitches those artifacts together
before a snapshot is published or streamed to light clients. It reuses the
`LightClientSync` reconstruction engine so the same steps a peer executes at
runtime are exercised offline.

## Required inputs

The verifier loads three artifact sets:

1. **Snapshot metadata** – canonical manifests in
   `storage::snapshots::known_snapshot_sets` record the schema digest, parameter
   digest, and block heights contained in each published dataset. Every run must
   target an entry that matches the persisted pruning receipts for the cluster
   being audited.【F:storage/src/snapshots/mod.rs†L83-L151】
2. **Pruning receipts** – the pruning automation persists receipts and the
   `PersistedPrunerState` summary under the `fw-pruning-snapshot` prefix. The
   verifier reads those blobs from the operator’s Firewood store and refuses to
   continue if any receipt is missing or diverges from the canonical metadata
   set.【F:rpp/node/src/state_sync/light_client.rs†L40-L212】【F:rpp/node/src/state_sync/light_client.rs†L260-L331】
3. **Proof payloads** – snapshot plans include chunk-level pruning proofs,
   Merkle roots, and recursive light-client updates. The pipeline encodes each
   plan, chunk, and update into the same wire format the node streams to peers so
   all verification work happens through the production codecs.【F:rpp/node/src/state_sync/light_client.rs†L60-L221】

Operators can run the verifier directly against their storage backend via
`LightClientVerifier::run`, or reuse the integration tests in
`tests/state_sync/light_client.rs` to smoke-test new datasets before they reach
QA.【F:rpp/node/src/state_sync/light_client.rs†L24-L109】【F:tests/state_sync/light_client.rs†L20-L120】

## Verification stages

The verifier records every milestone as a `LightClientVerificationEvent`, which
is also exposed to the runtime RPC layer. The stages appear in the session log in
this order:

1. **Plan loaded and ingested** – the reconstruction engine builds a
   `StateSyncPlan`, then the verifier replays the plan through
   `LightClientSync::ingest_plan` so that chunk and update ordering matches the
   runtime pipeline.【F:rpp/node/src/state_sync/light_client.rs†L74-L147】
2. **Snapshot metadata validated** – pruning receipts are cross-checked against
   the canonical manifests. Layout versions, retention windows, state roots, and
   state commitments must match before chunk proofs are processed.【F:rpp/node/src/state_sync/light_client.rs†L213-L331】
3. **Chunk Merkle proofs verified** – every chunk payload is decoded, its tagged
   pruning commitments are authenticated, and Merkle roots are recomputed. Each
   successful chunk ingestion records the height range that has been proven.【F:rpp/node/src/state_sync/light_client.rs†L148-L213】
4. **Recursive proofs verified** – the light-client updates included in the plan
   are replayed through the recursive verifier, ensuring commitment chaining is
   intact and that the verification cache reports success.【F:rpp/node/src/state_sync/light_client.rs†L181-L205】
5. **Snapshot root sealed** – once every update passes, the chunk roots are
   folded into the final snapshot root, `LightClientVerificationEvent::VerificationCompleted`
   marks the session as verified, and the summary report is emitted.【F:rpp/node/src/state_sync/light_client.rs†L205-L221】

When a stage fails the builder captures the exact error message and finalizes a
`StateSyncVerificationReport` that downstream tooling can persist or surface to
operators.【F:rpp/node/src/state_sync/light_client.rs†L332-L424】

## Observability and RPC integration

Runtime nodes expose the verification status over REST and an SSE head stream:

- `GET /state-sync/session` returns the active session snapshot. The payload
  includes the root commitment (if known), total chunk count, served chunk
  indexes, verification flag, last completed `LightClientVerificationEvent`, a
  human-readable progress log, and the last error (if any).【F:rpp/rpc/src/routes/state_sync.rs†L20-L94】
- `GET /state-sync/chunk/:id` fetches a specific chunk and embeds the same
  session status alongside the chunk metadata and payload. Clients can resume
  chunk downloads while tracking verification progress in a single response.【F:rpp/rpc/src/routes/state_sync.rs†L95-L181】
- `GET /state-sync/head/stream` upgrades to an SSE stream that emits
  `LightHeadSse` events as the light client advances. Each event reports the
  current height, block hash, state root, recursive proof commitment, an emission
  timestamp, and whether the head is finalized.【F:rpp/rpc/src/routes/state_sync.rs†L55-L94】【F:rpp/rpc/api.rs†L122-L162】

The RPC layer mirrors verification failures from the runtime, so clients can
surface metadata mismatches, missing receipts, or proof errors immediately. Unit
and integration tests cover the REST and SSE routes to guarantee these payloads
stay stable as the pipeline evolves.【F:rpp/rpc/tests/state_sync.rs†L71-L436】

## CI and automation hooks

State sync validation is wired into the light-client tests and helper routines in
`tests/support/sync.rs`. CI jobs or release pipelines can invoke the helpers to
assemble plans, collect artifacts, and assert that every verification stage
completes before publishing a new snapshot set.【F:tests/support/sync.rs†L91-L188】
