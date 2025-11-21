# RPC Payload Schemas

The public HTTP API exposes a stable set of request and response bodies. The following tables link to JSON Schema snapshots and canonical examples which are validated by module-level unit tests.

| Endpoint payload | Schema | Example |
| ---------------- | ------ | ------- |
| Runtime mode query response | [`runtime_mode_response.jsonschema`](rpc/runtime_mode_response.jsonschema) | [`examples/runtime_mode_response.json`](rpc/examples/runtime_mode_response.json) |
| Transaction signing request | [`sign_tx_request.jsonschema`](rpc/sign_tx_request.jsonschema) | [`examples/sign_tx_request.json`](rpc/examples/sign_tx_request.json) |
| Transaction signing response | [`sign_tx_response.jsonschema`](rpc/sign_tx_response.jsonschema) | [`examples/sign_tx_response.json`](rpc/examples/sign_tx_response.json) |
| Pipeline wait request | [`pipeline_wait_request.jsonschema`](rpc/pipeline_wait_request.jsonschema) | [`examples/pipeline_wait_request.json`](rpc/examples/pipeline_wait_request.json) |
| Pipeline wait response | [`pipeline_wait_response.jsonschema`](rpc/pipeline_wait_response.jsonschema) | [`examples/pipeline_wait_response.json`](rpc/examples/pipeline_wait_response.json) |
| Error envelope | [`error_response.jsonschema`](rpc/error_response.jsonschema) | [`examples/error_response.json`](rpc/examples/error_response.json) |

Schemas reference the runtime definitions where applicable to reduce duplication. Updates to these payloads should update both the schema snapshot and the corresponding example to keep the tests green.

## Error Envelope Codes

The `error_response.jsonschema` envelope now exposes an optional `code` field so
clients can react programmatically to verifier failures instead of scraping
messages. The state-sync verifier reports the following codes:

| Code | Meaning | Troubleshooting |
| ---- | ------- | --------------- |
| `state_sync_plan_invalid` | Snapshot plan could not be built. | Regenerate the plan and confirm the manifest hash matches the node configuration. |
| `state_sync_proof_encoding_invalid` | Proof bytes were malformed or truncated. | Re-download the proof chunk, verify the base64 payload length, and check `max_proof_size_bytes` isn’t clipping the payload. |
| `state_sync_metadata_mismatch` | Chunk metadata diverged from the expected snapshot. | Compare the announced root/height with peers and restart the sync session to pull a fresh plan. |
| `state_sync_verification_incomplete` | Verification bailed out before consuming all chunks. | Resume the session from the first missing chunk; if the error recurs, restart the sync workflow. |
| `state_sync_verifier_io` | I/O error while decoding or hashing the proof. | Inspect disk/permissions for the snapshot store and retry once storage is healthy. |
| `state_sync_pipeline_error` | Internal verifier pipeline failure. | Check runtime logs for the pipeline stage that failed and restart the node if the stage cannot recover. |
| `state_sync_pruner_state_error` | Persisted pruning state is inconsistent. | Rebuild the pruning state or clear the cache before retrying the session. |

Responses always include a human-readable `error` string; the optional `code`
field only appears when the server can map a verifier failure to one of the
known categories.
