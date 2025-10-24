# Interface Schema Changelog

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
