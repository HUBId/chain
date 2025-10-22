# Runtime Payload Schemas

The runtime surfaces several payloads over serde-compatible channels. Each schema is versioned as of this snapshot and accompanied by a representative example document that is exercised by unit tests.

| Topic | Schema | Example |
| ----- | ------ | ------- |
| Transaction payload | [`transaction.jsonschema`](runtime/transaction.jsonschema) | [`examples/transaction.json`](runtime/examples/transaction.json) |
| Signed transaction wrapper | [`signed_transaction.jsonschema`](runtime/signed_transaction.jsonschema) | [`examples/signed_transaction.json`](runtime/examples/signed_transaction.json) |
| Transaction envelope (hash + signed tx) | [`transaction_envelope.jsonschema`](runtime/transaction_envelope.jsonschema) | [`examples/transaction_envelope.json`](runtime/examples/transaction_envelope.json) |
| Uptime claim metadata | [`uptime_claim.jsonschema`](runtime/uptime_claim.jsonschema) | [`examples/uptime_claim.json`](runtime/examples/uptime_claim.json) |
| Uptime proof submission | [`uptime_proof.jsonschema`](runtime/uptime_proof.jsonschema) | [`examples/uptime_proof.json`](runtime/examples/uptime_proof.json) |

Each schema follows JSON Schema draft 2020-12 and is intended to remain backward compatible for consumers. Fields sourced from reusable runtime types (such as transactions) reference their canonical schema IDs so downstream tooling can resolve shared definitions.
