# Interface Specification

This reference collates the canonical payload contracts that are exercised by
`rpp` and `rpp_p2p`. Every schema listed below ships with an example document and
is validated by automated tests so CI fails whenever the implementation drifts
from the documented wire format.

## Gossip Topics

| Topic | Schema(s) | Producer(s) | Validation |
| --- | --- | --- | --- |
| Blocks (`/rpp/gossip/blocks/1.0.0`) | [`gossip_block.jsonschema`](p2p/gossip_block.jsonschema)【F:docs/interfaces/p2p/gossip_block.jsonschema†L1-L119】 | `NodeInner` fans block proposals into the witness gossip channel before forwarding them to libp2p.【F:rpp/runtime/node.rs†L700-L750】 | `gossip_block_schema_matches_example` validates the schema against the canonical sample payload.【F:rpp/p2p/src/pipeline.rs†L2354-L2360】 |
| Votes (`/rpp/gossip/votes/1.0.0`) | [`gossip_vote.jsonschema`](p2p/gossip_vote.jsonschema)【F:docs/interfaces/p2p/gossip_vote.jsonschema†L1-L24】 | Consensus votes are published through the same witness fan-out and ingested from libp2p gossip events.【F:rpp/runtime/node.rs†L2544-L2680】 | `gossip_vote_schema_matches_example` checks the schema/example pair in CI.【F:rpp/p2p/src/pipeline.rs†L2362-L2368】 |
| Proof bundles (`/rpp/gossip/proofs/1.0.0`, `/rpp/gossip/witness/proofs/1.0.0`) | [`witness_proof_summary.jsonschema`](p2p/witness_proof_summary.jsonschema)【F:docs/interfaces/p2p/witness_proof_summary.jsonschema†L1-L120】 | Proof summaries are pushed whenever the node completes witness generation and are replayed for downstream wallets via the witness channels.【F:rpp/runtime/node.rs†L700-L750】 | `witness_proof_summary_schema_matches_example` guards the schema snapshot.【F:rpp/p2p/src/pipeline.rs†L2386-L2392】 |
| VRF proofs (`/rpp/gossip/vrf/proofs/1.0.0`) | [`vrf_proof.jsonschema`](p2p/vrf_proof.jsonschema)【F:docs/interfaces/p2p/vrf_proof.jsonschema†L1-L58】 | VRF submissions received over gossip are funneled into the VRF mempool and epoch manager.【F:rpp/runtime/node.rs†L2544-L2680】 | `vrf_proof_schema_matches_example` validates the canonical submission payload.【F:rpp/p2p/src/pipeline.rs†L2370-L2376】 |
| Snapshot stream (`/rpp/gossip/snapshots/1.0.0`) | [`state_sync_chunk_stream.jsonschema`](p2p/state_sync_chunk_stream.jsonschema)【F:docs/interfaces/p2p/state_sync_chunk_stream.jsonschema†L1-L26】 | State sync chunk streams are emitted by the snapshot store and forwarded over gossip to catch-up peers.【F:rpp/runtime/node.rs†L2544-L2680】 | `snapshot_chunk_stream_schema_matches_example` validates the chunk stream schema.【F:rpp/p2p/src/pipeline.rs†L2378-L2384】 |
| Meta telemetry (`/rpp/gossip/meta/1.0.0`) | Telemetry (`meta_telemetry.jsonschema`), Timetoke deltas (`meta_timetoke.jsonschema`), evidence (`meta_evidence.jsonschema`), feature announcements (`meta_feature_announcement.jsonschema`), reputation updates (`meta_reputation.jsonschema`).【F:docs/interfaces/p2p/meta_telemetry.jsonschema†L1-L29】【F:docs/interfaces/p2p/meta_timetoke.jsonschema†L1-L20】【F:docs/interfaces/p2p/meta_evidence.jsonschema†L1-L26】【F:docs/interfaces/p2p/meta_feature_announcement.jsonschema†L1-L25】【F:docs/interfaces/p2p/meta_reputation.jsonschema†L1-L28】 | Witness telemetry, timetoke, and evidence reports are relayed through the node’s meta channel before being fanned out to subscribers.【F:rpp/runtime/node.rs†L700-L750】 | Schema checks cover each payload family (`meta_telemetry_schema_roundtrip`, `meta_timetoke_schema_matches_example`, `meta_evidence_schema_matches_example`, `meta_feature_announcement_schema_matches_example`, `meta_reputation_schema_matches_example`).【F:rpp/p2p/src/pipeline.rs†L2338-L2352】【F:rpp/p2p/src/pipeline.rs†L2410-L2432】 |
| Witness meta (`/rpp/gossip/witness/meta/1.0.0`) | [`witness_meta_evidence.jsonschema`](p2p/witness_meta_evidence.jsonschema)【F:docs/interfaces/p2p/witness_meta_evidence.jsonschema†L1-L30】 | Witness attestations are rebroadcast through the dedicated witness meta channel, sharing the same publisher as the proof stream.【F:rpp/runtime/node.rs†L700-L750】 | `witness_meta_evidence_schema_matches_example` locks the schema/example pair in CI.【F:rpp/p2p/src/pipeline.rs†L2418-L2423】 |

## RPC Endpoints

| Endpoint(s) | Method(s) | Schema(s) | Handler | Validation |
| --- | --- | --- | --- | --- |
| `/runtime/mode` | GET / POST | Response: [`runtime_mode_response.jsonschema`](rpc/runtime_mode_response.jsonschema)【F:docs/interfaces/rpc/runtime_mode_response.jsonschema†L1-L33】 | `runtime_mode` and `update_runtime_mode` expose and mutate the runtime state toggle.【F:rpp/rpc/api.rs†L1576-L1585】 | `runtime_mode_response_schema_roundtrip` ensures the schema and example stay in sync.【F:rpp/rpc/api.rs†L3044-L3050】 |
| `/wallet/tx/sign` | POST | Request: [`sign_tx_request.jsonschema`](rpc/sign_tx_request.jsonschema); Response: [`sign_tx_response.jsonschema`](rpc/sign_tx_response.jsonschema)【F:docs/interfaces/rpc/sign_tx_request.jsonschema†L1-L21】【F:docs/interfaces/rpc/sign_tx_response.jsonschema†L1-L18】 | `wallet_sign_transaction` accepts a signing request and returns the signed transaction envelope.【F:rpp/rpc/api.rs†L2413-L2420】 | `sign_tx_request_schema_roundtrip` / `sign_tx_response_schema_roundtrip` verify both payloads.【F:rpp/rpc/api.rs†L3052-L3066】 |
| `/wallet/pipeline/wait` | POST | Request: [`pipeline_wait_request.jsonschema`](rpc/pipeline_wait_request.jsonschema); Response: [`pipeline_wait_response.jsonschema`](rpc/pipeline_wait_response.jsonschema)【F:docs/interfaces/rpc/pipeline_wait_request.jsonschema†L1-L24】【F:docs/interfaces/rpc/pipeline_wait_response.jsonschema†L1-L23】 | `wallet_pipeline_wait` coordinates with the pipeline orchestrator to block until the requested stage completes.【F:rpp/rpc/api.rs†L2595-L2613】 | `pipeline_wait_request_schema_roundtrip` / `pipeline_wait_response_schema_roundtrip` enforce the contract.【F:rpp/rpc/api.rs†L3068-L3081】 |
| Shared error envelope | any | [`error_response.jsonschema`](rpc/error_response.jsonschema)【F:docs/interfaces/rpc/error_response.jsonschema†L1-L23】 | Every handler returns the shared error envelope on failure via `to_http_error`.【F:rpp/rpc/api.rs†L2413-L2443】【F:rpp/rpc/api.rs†L2595-L2613】 | `error_response_schema_roundtrip` keeps the canonical error payload in sync.【F:rpp/rpc/api.rs†L3084-L3088】 |

## State Transitions

- The `StateLifecycleService` trait defines the `apply_block`, `prove_transition`,
  `verify_transition`, and accessor hooks that drive Firewood state changes and
  proof verification.【F:rpp/storage/state/lifecycle.rs†L13-L86】
- `StateTransitionReceipt` captures the previous and new Firewood state roots and
  any pruning proof emitted during the transition.【F:rpp/storage/mod.rs†L40-L45】
- The receipt is documented by [`state_transition_receipt.jsonschema`](runtime/state_transition_receipt.jsonschema) with an accompanying example payload.【F:docs/interfaces/runtime/state_transition_receipt.jsonschema†L1-L40】【F:docs/interfaces/runtime/examples/state_transition_receipt.json†L1-L15】
- Storage unit tests compile the schema, validate the example, and round-trip it
  through `StateTransitionReceipt` to catch drift in CI.【F:rpp/storage/mod.rs†L47-L120】

