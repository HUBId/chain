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
