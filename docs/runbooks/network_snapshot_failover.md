# Network snapshot failover runbook

Use this runbook when snapshot consumers stall, resume attempts fail, or alerts
flag stalled `/p2p/snapshots` sessions. It complements the
[snapshot observability guide](../observability/network_snapshots.md) and the
[pipeline dashboards](../observability/pipeline.md) so on-call engineers can
trace RPC failures back to the producing validator and confirm recovery.

## Detection

Investigate a failover when any of the following signals trigger:

- Grafana or Prometheus alerts for `snapshot_stream_lag_seconds` crossing the
  30 s warning or 120 s critical threshold, signalling stalled chunk delivery.
- Spikes in `light_client_chunk_failures_total{kind="chunk"}` or
  `snapshot_bytes_sent_total{kind="chunk"}` dropping to zero while a session
  remains active.
- `rpp_node_pipeline_root_io_errors_total` increments, indicating Firewood
  storage or snapshot corruption during chunk replay.
- `snapshot_chunk_checksum_failures_total{kind="checksum_mismatch"}` increases,
  signalling the background validator found corrupted on-disk snapshot chunks;
  inspect the accompanying `snapshot_validator` warnings and the manifest in the
  node’s snapshot directory to confirm which files were affected.【F:rpp/node/src/services/snapshot_validator.rs†L1-L205】

The checksum worker runs every `snapshot_validator.cadence_secs` (five minutes by
default) and survives process restarts: after the service comes back up it
emits the `snapshot chunk validation failed` warning and bumps the checksum
metric again within the configured cadence.【F:rpp/runtime/config.rs†L1294-L1299】【F:rpp/node/src/services/snapshot_validator.rs†L74-L113】【F:tests/network/snapshot_checksum_restart.rs†L21-L178】

These metrics and alert thresholds are documented in the snapshot and pipeline
observability references; keep those dashboards open while running this
playbook.【F:docs/observability/network_snapshots.md†L1-L74】【F:docs/observability/pipeline.md†L22-L96】

## Prerequisites

1. Export the RPC bearer token into your shell: `export RPP_RPC_TOKEN=...`.
2. Identify the stalled consumer host and port (usually the validator RPC
   endpoint).
3. Confirm the session identifier from the alert, log message, or via
   `GET /p2p/snapshots`.

All snapshot RPC calls require the `Authorization: Bearer` header whenever RPC
authentication is enabled; missing headers return `401 Unauthorized`.【F:docs/network/snapshots.md†L74-L117】

### Automated health audit

The nightly workflow runs `cargo xtask snapshot-health` against the production
validator RPC and persists the JSON report as the `snapshot-health-report`
artifact. The task invokes `rpp-node validator snapshot status` for every active
session, cross-checks the reported chunk/update indices against the local
manifest totals, and emits structured JSON logs so any divergence fails the job
and pages on-call engineers.【F:.github/workflows/nightly.yml†L29-L64】【F:xtask/src/main.rs†L214-L596】

Nightly verification also requires access to the pruning chunk set referenced
by the manifest. Configure the `SNAPSHOT_CHUNK_ARCHIVE_URL` secret with an HTTP
or S3 location of the archived `cf_pruning_snapshots` directory. The workflow
downloads the archive, extracts it into `SNAPSHOT_CHUNK_ROOT`, and passes that
path to the snapshot verification tooling; missing or unreachable archives fail
the job so maintainers are alerted to expired artifacts.【F:.github/workflows/nightly.yml†L46-L134】

If the archive secret is not configured the nightly job emits a warning and
skips the download step so the remainder of the health audit can still run;
configure the secret as soon as the archive location is known to restore full
coverage.【F:.github/workflows/nightly.yml†L96-L122】

When investigating a snapshot incident, re-run the audit locally to capture the
current state before making changes. Configure the RPC endpoint and optional
manifest overrides via environment variables, then write the report to disk for
the incident log:

```sh
export SNAPSHOT_RPC_URL="https://validator.example.net:7070"
export SNAPSHOT_RPC_TOKEN="$(pass snapshots/prod-token)"
export SNAPSHOT_MANIFEST_PATH="/var/lib/rpp-node/snapshots/manifest/chunks.json"
cargo xtask snapshot-health \
  --config /etc/rpp/validator.toml \
  --output snapshot-health-report.json
```

The command prints per-session JSON entries highlighting any anomalies and exits
non-zero if a session stalls, reports an error string, or exceeds the manifest
totals. Attach the generated report to the incident timeline so it can be
compared with the nightly artifact.【F:xtask/src/main.rs†L214-L596】

## Step 1 – Verify control-plane health

1. List active sessions:
   ```sh
   curl -sS \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     http://<consumer-host>:<port>/p2p/snapshots
   ```
   A healthy response returns `200 OK` with an array of `SnapshotStreamStatus`
   entries. `404 Not Found` indicates the session expired or never existed. The
   CLI alternative auto-loads the RPC URL/token from `validator.toml`:
   ```text
  rpp-node validator snapshot status --session <session>
  snapshot status:
    session: <session>
    peer: 12D3KooW...
    root: deadbeef...
    plan_id: deadbeef...
    last_chunk_index: 12
    last_update_index: 3
    last_update_height: 256
    verified: false
    error: none
   ```
2. Inspect the stalled session directly to capture its last confirmed chunk and
   error string:
   ```sh
   curl -sS \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     http://<consumer-host>:<port>/p2p/snapshots/<session> | jq
   ```
   `rpp-node validator snapshot status --session <session>` prints the same
   fields and propagates RPC failures verbatim (for example: `RPC returned 404:
   snapshot session <session> not found`). Record any `error:` value for the
   incident log.

## Step 2 – Restart the producer (if required)

If the provider validator crashed or shows storage errors:

1. Restart the service (example for systemd-managed nodes):
   ```sh
   sudo systemctl restart rpp-node
   ```
2. Tail the logs for `snapshot provider started` and confirm the node rejoins the
   mesh via `/p2p/peers`.
3. Re-run Step 1 to ensure the consumer can still reach the session record. The
   session persists across restarts, so the consumer can resume once the producer
   advertises fresh chunks.【F:docs/network/snapshots.md†L1-L73】
4. Watch the checksum validator logs/metrics after the restart; they should fire
   within the cadence window and confirm the node is still scanning its local
   snapshots.【F:rpp/node/src/services/snapshot_validator.rs†L74-L153】【F:tests/network/snapshot_checksum_restart.rs†L92-L163】

## Step 3 – Replay missing chunks

1. Capture the last confirmed chunk from the session status (field
   `confirmed_chunk_index`).
2. Issue a resume request targeting the same provider peer:
   ```sh
   curl -sS -X POST \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
   -d '{
          "peer":"<provider-peer-id>",
          "chunk_size":32768,
          "resume":{"session":<session>,"plan_id":"<plan-id>"}
        }' \
   http://<consumer-host>:<port>/p2p/snapshots
   ```
   The equivalent CLI shortcut handles authentication automatically:
   ```text
   rpp-node validator snapshot resume --session <session> --peer <provider-peer-id> --plan-id <plan-id>
   snapshot session resumed:
     session: <session>
     peer: <provider-peer-id>
     root: deadbeef...
     plan_id: deadbeef...
     last_chunk_index: 327
     last_update_index: 12
     last_update_height: 4096
     verified: false
     error: none
   ```
   - `200 OK` (or a successful CLI invocation) confirms the resume succeeded and
     returns the refreshed status.
   - `500 Internal Server Error` with
     `"precedes next expected chunk"` or
     `"skips ahead of next expected chunk"` means the request regressed or
     skipped offsets. Use the last confirmed chunk from Step 1 and try again.
   - `500 Internal Server Error` with `"plan id"` indicates the provider has
     rotated to a different snapshot plan; fetch the latest status to obtain the
     new `plan_id` before retrying.
3. Poll the session until `verified=true` and `error=null`:
   ```sh
   curl -sS \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     http://<consumer-host>:<port>/p2p/snapshots/<session> \
     | jq '{session,last_chunk_index,confirmed_chunk_index,verified,error}'
   ```
   or via CLI:
   ```text
   rpp-node validator snapshot status --session <session>
   ```

The resume semantics and error payloads mirror the behaviour exercised by the
network integration tests, providing a reproducible path to validate tooling and
incident simulations.【F:docs/network/snapshots.md†L32-L73】【F:tests/network/snapshots_resume.rs†L1-L210】

## Step 4 – Validate recovery

1. Watch `snapshot_bytes_sent_total{kind="chunk"}` recover to a steady rate on
   the producer dashboard and ensure
   `snapshot_stream_lag_seconds` falls back below the warning threshold.
2. Confirm `light_client_chunk_failures_total` stops increasing on both producer
   and consumer panels.
3. Inspect `rpp_node_pipeline_root_io_errors_total`; it should remain flat after
   the replay completes.
4. Optionally rerun the snapshot resume integration test in a staging or simnet
   cluster to confirm the environment matches CI coverage:
   ```sh
   cargo test -p tests --test snapshots_resume
   ```
   The test reproduces chunk inflation/deflation scenarios and asserts the RPC
   returns the expected `500` errors when offsets drift, ensuring regressions are
   caught before production rollouts.【F:tests/network/snapshots_resume.rs†L1-L310】

Record the outcome, metrics, and any configuration adjustments in the incident
log before closing the alert.

## Expected error codes

| Endpoint | Scenario | Status | Notes |
| --- | --- | --- | --- |
| `POST /p2p/snapshots` / `rpp-node validator snapshot start` | Start/resume with valid offsets | `200 OK` | Returns `SnapshotStreamStatus` with updated indices. |
| `POST /p2p/snapshots` / `rpp-node validator snapshot resume` | Resume with regressed offsets | `500 Internal Server Error` | Error message contains `"precedes next expected chunk"`. |
| `POST /p2p/snapshots` / `rpp-node validator snapshot resume` | Resume skipping ahead | `500 Internal Server Error` | Error message contains `"skips ahead of next expected chunk"`. |
| `POST /p2p/snapshots` / `rpp-node validator snapshot resume` | Resume with mismatched plan | `500 Internal Server Error` | Error message contains `"plan id"`; fetch the latest status to obtain the new `plan_id`. |
| `DELETE /p2p/snapshots/<session>` / `rpp-node validator snapshot cancel` | Cancel active session | `204 No Content` | Removes the persisted session; follow with `status` to confirm deletion. |
| `GET /p2p/snapshots/<session>` / `rpp-node validator snapshot status` | Unknown session ID | `404 Not Found` | Indicates record expired or was cleared. |
| Any snapshot endpoint | Missing/invalid bearer token | `401 Unauthorized` | Add `Authorization: Bearer ${RPP_RPC_TOKEN}` header or rely on the CLI’s auto-injected token. |

Error semantics match the documented RPC contract and the regression coverage in
`snapshots_resume.rs`, so successful retries confirm the incident has been
resolved and instrumentation remains intact.【F:docs/network/snapshots.md†L32-L117】【F:tests/network/snapshots_resume.rs†L1-L310】
