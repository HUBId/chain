# Validator Tooling

The validator CLI and RPC server expose a toolkit for managing VRF secrets,
inspecting gossip telemetry, and now monitoring light-client state-sync
progress without restarting the node. The CLI wraps the new RPC endpoints so
operators can automate key rotations, incident response, or snapshot recovery
directly from the host.

## CLI subcommands

The CLI offers dedicated namespaces for validator operations and the
light-client helpers that drive state sync.

### `rpp-node validator`

The `rpp-node validator` namespace bundles two feature areas:

1. **VRF key management**
   * Rotate the VRF keypair and persist it through the configured secrets
     backend:

     ```sh
     rpp-node validator vrf rotate --config config/validator.toml
     ```

     The command prints the backend, resolved identifier, and new public key so
     operators can verify that the correct secret store was updated. Existing
     material is overwritten atomically.【F:rpp/node/src/main.rs†L92-L122】

   * Inspect the stored key (both public and secret components) to confirm that
     a rotation succeeded or to sanity-check a bootstrap install:

     ```sh
     rpp-node validator vrf inspect --config config/validator.toml
     ```

   * Export the keypair as JSON. By default the payload is written to stdout;
     pass `--output <path>` to persist it for off-host backups or secrets
     replication workflows.【F:rpp/node/src/main.rs†L124-L158】

2. **Telemetry snapshots**
   * Query the RPC server for the latest meta telemetry report and print the
     JSON response. Use `--pretty` to format the payload:

     ```sh
     rpp-node validator telemetry --rpc-url http://127.0.0.1:7070 --pretty
     ```

     The command transparently forwards any RPC authentication token supplied
     via `--auth-token` and surfaces HTTP errors verbatim so operators can spot
     tier-gating failures or connectivity issues.【F:rpp/node/src/main.rs†L160-L203】

### `rpp-node light-client`

State-sync operations for light clients and snapshot mirroring now ship as
first-class CLI helpers. All light-client commands require the RPC base URL;
pass `--rpc-url http://host:port` (defaults to `http://127.0.0.1:7070`) and
forward any bearer token via `--auth-token <token>` to satisfy secured
deployments.

* Follow the latest verified light-client head and stream subsequent updates as
  newline-delimited JSON (one event per line) rendered from the
  [`/state-sync/head` payload schema](./interfaces/rpc/state_sync_head_response.jsonschema):

  ```sh
  rpp-node light-client head-follow \
    --rpc-url http://127.0.0.1:7070 \
    --auth-token "$RPP_RPC_TOKEN"
  ```

  The command establishes an SSE connection to `/state-sync/head/stream` and
  prints the decoded event payload. Use standard UNIX tooling such as
  `jq --unbuffered` or `awk` to alert on height gaps or stale timestamps.

* Retrieve an individual snapshot chunk and persist the decoded payload, with a
  JSON summary that matches the
  [`/state-sync/chunk/:id` schema](./interfaces/rpc/state_sync_chunk_response.jsonschema):

  ```sh
  rpp-node light-client fetch-chunk \
    --rpc-url http://127.0.0.1:7070 \
    --chunk-id 12 \
    --output chunk-12.bin
  ```

  When `--output` is provided the tool base64-decodes the payload into the
  chosen file and echoes the chunk metadata (root, index, total, checksum) to
  stdout so operators can script integrity checks before applying the chunk.

Both commands fail fast if the node rejects the request (for example, because a
state-sync session has not been prepared) and bubble up the structured error
payload emitted by the RPC server.

## RPC endpoints

The RPC server now exposes dedicated validator tooling routes and enforces a
simple authorization policy: requests succeed if the node is configured with an
RPC auth token _or_ the embedded wallet reports a validator tier (currently
Tier 0 or higher). Nodes running without a wallet will receive a 403 response
detailing the missing requirement.【F:rpp/rpc/api.rs†L48-L95】【F:rpp/rpc/api.rs†L640-L678】

The endpoints return structured JSON documented under `docs/interfaces/rpc/`:

| Route | Method | Description |
| ----- | ------ | ----------- |
| `/validator/vrf` | `GET` | Returns the backend, identifier, and public key if one is present.【F:rpp/rpc/api.rs†L905-L914】【F:docs/interfaces/rpc/validator_vrf_response.jsonschema†L1-L19】 |
| `/validator/vrf/rotate` | `POST` | Generates a fresh VRF keypair, stores it via the configured secrets backend, and returns the same payload as the `GET` endpoint.【F:rpp/rpc/api.rs†L916-L926】【F:docs/interfaces/rpc/validator_vrf_rotate_response.jsonschema†L1-L19】 |
| `/validator/telemetry` | `GET` | Aggregates rollout, node, consensus, and mempool telemetry for operator dashboards.【F:rpp/rpc/api.rs†L1246-L1271】【F:docs/interfaces/rpc/validator_telemetry_response.jsonschema†L1-L104】 |
| `/state-sync/head` | `GET` | Returns the latest verified light-client head. The streaming variant at `/state-sync/head/stream` emits the same payload as SSE events.【F:rpp/rpc/api.rs†L79-L117】【F:docs/interfaces/rpc/state_sync_head_response.jsonschema†L1-L38】 |
| `/state-sync/chunk/:id` | `GET` | Retrieves a specific snapshot chunk for the active state-sync session. Chunk indices must be in-range for the advertised session metadata.【F:rpp/rpc/api.rs†L1139-L1180】【F:docs/interfaces/rpc/state_sync_chunk_response.jsonschema†L1-L35】 |

Example requests:

```sh
# Fetch the current VRF state
curl -s http://127.0.0.1:7070/validator/vrf | jq

# Rotate the VRF key; errors propagate as JSON (403 if tier gating fails)
curl -sX POST http://127.0.0.1:7070/validator/vrf/rotate | jq

# Inspect validator telemetry highlights
curl -s http://127.0.0.1:7070/validator/telemetry | jq '{height: .node.height, uptime: .mempool.uptime_proofs}'
```

When a request violates the auth policy the server responds with HTTP 403 and a
message similar to `validator tier New does not meet required tier Trusted`.
Supply the configured bearer token or run the validator with a wallet so the
tier check can succeed.【F:rpp/rpc/api.rs†L73-L94】

## Error handling and operational tips

* **Stateless CLI commands**: the CLI never mutates node runtime state beyond
  updating the VRF secrets store. Restart the node after rotating keys to load
  the new material into memory.【F:rpp/node/src/main.rs†L92-L122】
* **Export hygiene**: the exported VRF secret is delivered as JSON; treat it as
  sensitive material and remove the file after uploading it to your secret
  store.【F:rpp/node/src/main.rs†L124-L158】
* **Rate limiting**: telemetry requests respect the global RPC rate limiter, so
  avoid polling the endpoint faster than the configured `rpc_requests_per_minute`.
