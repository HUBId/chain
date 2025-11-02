# Consensus API Reference

## `/consensus/proof/status`

Returns the most recent consensus certificate metadata together with the Poseidon
bindings that the proof circuits enforce.

- **Method:** `GET`
- **Query parameters:**
  - `version` (optional, integer): schema version to return. Defaults to `2`.
    * `1` – legacy payload with raw metadata only.
    * `2` – extends the payload with binding digests (`vrf_output`,
      `witness_commitment_root`, etc.).
- **Response schema:** [`consensus_proof_status_response.jsonschema`](../interfaces/rpc/consensus_proof_status_response.jsonschema)
- **Example:** [`examples/consensus_proof_status_response.json`](../interfaces/rpc/examples/consensus_proof_status_response.json)

```bash
curl "https://rpc.rpp.dev/consensus/proof/status?version=2"
```

### Example payload (version 2)

```json
{
  "version": 2,
  "height": 128,
  "round": 7,
  "block_hash": "…",
  "vrf_outputs": ["…"],
  "quorum_signature_root": "…",
  "vrf_output": "…",
  "witness_commitment_root": "…",
  "quorum_signature": "…"
}
```

Clients that still rely on the legacy payload can request `version=1` to receive
the same fields they consumed before the bindings were introduced.

### Fields

| Field | Description |
| --- | --- |
| `vrf_output`, `vrf_proof` | Poseidon bindings folding the block hash with all VRF outputs / proofs. |
| `witness_commitment_root` | Binding digest over witness commitments. |
| `reputation_root` | Binding digest over the reputation tree roots. |
| `quorum_bitmap`, `quorum_signature` | Bindings that tie quorum digests to the block hash. |

The bindings are omitted when requesting `version=1` to keep backwards
compatibility with earlier clients.

### Acceptance criteria

1. **Metadata passthrough** – The raw metadata (`vrf_outputs`, `witness_commitments`, etc.) is forwarded unchanged from the consensus certificate. Verified by the unit test
   `summarize_consensus_certificate_includes_bindings` in
   [`rpp/runtime/node.rs`](../../rpp/runtime/node.rs).
2. **Binding digests** – The new binding fields (`vrf_output`,
   `witness_commitment_root`, `quorum_bitmap`, …) match the Poseidon folds that the
   consensus circuit enforces. Also covered by
   `summarize_consensus_certificate_includes_bindings` and by the regression tests in
   [`tests/consensus/consensus_proof_integrity.rs`](../../tests/consensus/consensus_proof_integrity.rs).

When either criterion fails, the route returns `503 Service Unavailable` until the
runtime records a valid certificate again.
