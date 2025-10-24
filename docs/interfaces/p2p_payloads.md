# P2P Payload Schemas

Gossip and state sync exchanges rely on structured payloads shared between nodes. The artifacts below capture the canonical JSON representation for each topic, with examples that are exercised by the `rpp-p2p` test-suite.

| Topic | Schema | Example |
| ----- | ------ | ------- |
| Global state commitments | [`network_global_state_commitments.jsonschema`](p2p/network_global_state_commitments.jsonschema) | [`examples/network_global_state_commitments.json`](p2p/examples/network_global_state_commitments.json) |
| Block proposal gossip | [`gossip_block.jsonschema`](p2p/gossip_block.jsonschema) | [`examples/gossip_block.json`](p2p/examples/gossip_block.json) |
| Vote gossip | [`gossip_vote.jsonschema`](p2p/gossip_vote.jsonschema) | [`examples/gossip_vote.json`](p2p/examples/gossip_vote.json) |
| Block metadata | [`network_block_metadata.jsonschema`](p2p/network_block_metadata.jsonschema) | [`examples/network_block_metadata.json`](p2p/examples/network_block_metadata.json) |
| Payload expectations | [`network_payload_expectations.jsonschema`](p2p/network_payload_expectations.jsonschema) | [`examples/network_payload_expectations.json`](p2p/examples/network_payload_expectations.json) |
| Reconstruction request | [`network_reconstruction_request.jsonschema`](p2p/network_reconstruction_request.jsonschema) | [`examples/network_reconstruction_request.json`](p2p/examples/network_reconstruction_request.json) |
| State sync chunk | [`network_state_sync_chunk.jsonschema`](p2p/network_state_sync_chunk.jsonschema) | [`examples/network_state_sync_chunk.json`](p2p/examples/network_state_sync_chunk.json) |
| State sync chunk stream | [`state_sync_chunk_stream.jsonschema`](p2p/state_sync_chunk_stream.jsonschema) | [`examples/state_sync_chunk_stream.json`](p2p/examples/state_sync_chunk_stream.json) |
| Light client update | [`network_light_client_update.jsonschema`](p2p/network_light_client_update.jsonschema) | [`examples/network_light_client_update.json`](p2p/examples/network_light_client_update.json) |
| Light client head | [`network_light_client_head.jsonschema`](p2p/network_light_client_head.jsonschema) | [`examples/network_light_client_head.json`](p2p/examples/network_light_client_head.json) |
| Meta timetoke delta | [`meta_timetoke.jsonschema`](p2p/meta_timetoke.jsonschema) | [`examples/meta_timetoke.json`](p2p/examples/meta_timetoke.json) |
| State sync plan | [`network_state_sync_plan.jsonschema`](p2p/network_state_sync_plan.jsonschema) | [`examples/network_state_sync_plan.json`](p2p/examples/network_state_sync_plan.json) |

Referencing schemas use canonical IDs to enable downstream tooling to resolve dependencies without additional context.
