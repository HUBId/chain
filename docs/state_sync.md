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
- `GET /state-sync/session/stream` opens an SSE stream that first publishes the
  active session status and then streams verified snapshot chunks as they are
  served. Each chunk event embeds the same status payload as the REST response
  so clients can track progress without polling.【F:rpp/rpc/src/routes/state_sync.rs†L20-L204】【F:rpp/rpc/api.rs†L122-L162】

Every verification run now exposes a `request_id` in the session payloads above.
The same identifier is logged by the verifier and attached to the
`rpp_node_pipeline_root_io_errors_total` and
`rpp_node_pipeline_state_sync_tamper_total` counters, allowing operators to
cross-reference client reports with dashboard spikes and runtime logs.

The runtime records dedicated telemetry while serving chunks: stream starts,
per-chunk counters, per-stream chunk totals, active stream samples, last-chunk
age, and backpressure events are exported via the
`rpp.runtime.state_sync.stream.{starts,chunks,chunks_sent,active,last_chunk_age.seconds,backpressure}`
metrics.【F:rpp/runtime/telemetry/metrics.rs†L111-L139】【F:rpp/runtime/sync.rs†L386-L445】

### State-sync stream alerts

Operators can plug the state-sync stream telemetry into Prometheus/Alertmanager
to guard against stalled or slow sessions. The sample rules in
`ops/alerts/storage/state_sync_stream.yaml` flag moving-average chunk gaps above
30s/120s and stalled throughput below 0.1 chunks per second after recent
progress.【F:ops/alerts/storage/state_sync_stream.yaml†L1-L45】 These thresholds
match the runtime metrics listed above so on-call engineers can correlate alert
firings with chunk-level telemetry.

The RPC layer mirrors verification failures from the runtime, so clients can
surface metadata mismatches, missing receipts, or proof errors immediately. Unit
and integration tests cover the REST and SSE routes to guarantee these payloads
stay stable as the pipeline evolves.【F:rpp/rpc/tests/state_sync.rs†L71-L436】

### Snapshot download budgets

Snapshot streams now enforce two timing budgets sourced from the node
configuration. `snapshot_download.timetoke_budget_secs` limits how long a stream
can run before it risks invalidating time-toke accrual windows, while
`snapshot_download.uptime_budget_secs` caps total runtime to preserve uptime
reporting SLAs.【F:rpp/runtime/config.rs†L2680-L2811】【F:rpp/runtime/sync.rs†L334-L520】
Slow sessions that exceed either threshold abort with a `state sync exceeded
<budget> budget` error so operators can retry against healthier peers.【F:rpp/rpc/api.rs†L959-L1003】【F:rpp/runtime/sync.rs†L334-L520】

Recommended settings keep the timetoke budget under 15 minutes and the uptime
budget under 30 minutes, aligning with the default one-hour time-toke observation
window while leaving headroom for retries. Tune the values upward only after
confirming bandwidth constraints, since any overrun halts the stream early to
protect the reputation pipeline.【F:rpp/runtime/config.rs†L2680-L2811】

## CI and automation hooks

State sync validation is wired into the light-client tests and helper routines in
`tests/support/sync.rs`. CI jobs or release pipelines can invoke the helpers to
assemble plans, collect artifacts, and assert that every verification stage
completes before publishing a new snapshot set.【F:tests/support/sync.rs†L91-L188】

Wallet pipelines now run a dedicated state-sync reconciliation that rebuilds
pruned blocks and wallet account state across both prover backends. The
`wallet_state_sync_replays_accounts_across_backends` test builds a pruning plan,
reconstructs each requested block, and compares the resulting account map to the
seeded expectations; any hash or balance/nonce drift fails the run while
printing the backend label that diverged.【F:tests/state_sync_wallet.rs†L58-L106】

To reproduce the reconciliation locally, run the test once per backend and
preserve the log output for audit evidence:

```
RPP_PROVER_DETERMINISTIC=1 cargo test --locked --test state_sync_wallet \
  --features "wallet-integration,prover-stwo" -- --nocapture
RPP_PROVER_DETERMINISTIC=1 cargo test --locked --test state_sync_wallet \
  --features "wallet-integration,backend-rpp-stark" -- --nocapture
```

Each invocation emits a `state_sync_wallet.log` file in CI artifacts. When a
backend diverges, the assertion messages identify whether the reconstructed
block hashes or the wallet account balances failed to match. Correlate failures
with the runtime wallet telemetry that tracks prover backend outcomes and sync
progress to isolate the cause:

- `rpp.runtime.wallet.prover.jobs`/`rpp.runtime.wallet.prover.failures` record
  successes and error codes per backend, flagging prover-level regressions
  surfaced by the reconciliation run.【F:rpp/runtime/telemetry/metrics.rs†L188-L244】
- `rpp.runtime.wallet.sync.{wallet_height,chain_tip_height,lag.blocks}` expose
  the replayed height and observed lag, helping operators confirm whether the
  reconstructed plan stalled before the account map drifted.【F:rpp/runtime/telemetry/metrics.rs†L244-L276】
