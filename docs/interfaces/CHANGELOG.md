# Interface Schema Changelog

## 2025-12-05

- Added `state_sync_status_response.jsonschema` and updated
  `state_sync_chunk_response.jsonschema` to include the aggregated verification
  status returned by `/state-sync/session` and `/state-sync/chunk/:id`.
- Documented the progress log, served chunk list, and error fields surfaced by
  the new state sync RPC responses.

## 2025-11-29

- Added consolidated interface overview in `docs/interfaces/spec.md`, linking
  gossip topics, RPC endpoints, and state transition receipts to their schema
  snapshots and validation tests.
- Introduced `state_transition_receipt.jsonschema` with an accompanying example
  document and storage schema tests to cover Firewood transition receipts.

## 2025-10-24

- Added RPC schemas describing `/state-sync/head` and `/state-sync/chunk/:id`
  responses for light-client tooling.

## 2025-02-20

- Added LightClientHead and SnapshotChunkStream schemas with sample payloads for P2P state sync documentation.

## 2025-02-14

- Added canonical JSON Schema snapshots for runtime transaction and uptime payloads.
- Captured RPC request/response schemas for signing, runtime mode inspection, and pipeline wait operations.
- Documented P2P state sync payload schemas covering commitments, reconstruction requests, and light client updates.
- Introduced example documents for each schema and unit tests to validate round-trip serialization.
