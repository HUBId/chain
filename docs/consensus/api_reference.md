# Consensus API Reference

## `/consensus/proof/status`

Returns the most recent consensus certificate metadata together with the Poseidon
bindings that the proof circuits enforce.

- **Method:** `GET`
- **Query parameters:**
- `version` (optional, integer): schema version to return. Defaults to `3`.
  * `1` – legacy payload with raw metadata only.
  * `2` – extends the payload with binding digests (`vrf_output`,
    `witness_commitment_root`, etc.).
  * `3` – returns structured `vrf_entries` with randomness, pre-output, proof,
    public key, and Poseidon commitments. Legacy lists are derived on demand.
- **Response schema:** [`consensus_proof_status_response.jsonschema`](../interfaces/rpc/consensus_proof_status_response.jsonschema)
- **Example:** [`examples/consensus_proof_status_response.json`](../interfaces/rpc/examples/consensus_proof_status_response.json)

```bash
curl "https://rpc.rpp.dev/consensus/proof/status?version=3"
```

### Example payload (version 3)

```json
{
  "version": 3,
  "height": 128,
  "round": 7,
  "block_hash": "…",
  "vrf_entries": [
    {
      "randomness": "…",
      "pre_output": "…",
      "proof": "…",
      "public_key": "…",
      "poseidon": {
        "digest": "…",
        "last_block_header": "…",
        "epoch": "…",
        "tier_seed": "…"
      }
    }
  ],
  "vrf_output": "…",
  "witness_commitment_root": "…",
  "quorum_signature": "…"
}
```

Clients that still rely on the legacy payload can request `version=1` or
`version=2`. Version 2 continues to emit the derived VRF lists and aggregated
Poseidon roots; version 1 omits bindings entirely.

### Fields

| Field | Description |
| --- | --- |
| `vrf_entries[]` | Structured VRF transcripts containing randomness, pre-output, proof, public key, and Poseidon metadata (`digest`, `last_block_header`, `epoch`, `tier_seed`) for each validator. |
| `vrf_output`, `vrf_proof` | Poseidon bindings folding the block hash with all VRF pre-outputs / proofs. Present for versions ≥ 2. |
| `witness_commitment_root` | Binding digest over witness commitments. |
| `reputation_root` | Binding digest over the reputation tree roots. |
| `quorum_bitmap`, `quorum_signature` | Bindings that tie quorum digests to the block hash. |

The bindings are omitted when requesting `version=1` to keep backwards
compatibility with earlier clients. Version 3 keeps `vrf_outputs` and
`vrf_proofs` optional; when requested they are derived from the structured
entries (`vrf_entries[].pre_output` / `.proof`). Clients can safely migrate to
the new schema by prioritising `vrf_entries` and falling back to the legacy lists
only while older agents remain in the fleet.

### Client migration notes

- Prefer requesting `version=3` to receive the structured `vrf_entries`. Each
  entry already contains the validator's VRF public key; clients no longer need
  to hydrate this from the staking set.
- The nested `poseidon` object binds the transcript data to the advertised
  `block_hash`. Verifiers SHOULD recompute these bindings before trusting a
  transcript and compare them against the exported digests.
- If you still depend on the flat `vrf_outputs`/`vrf_proofs` arrays, request
  `version=2`. The RPC backend assembles them directly from the `vrf_entries`
  vector to maintain ordering guarantees.
- Downstream caches can detect the transition by inspecting the `version` field
  and retaining backwards-compatible decoding until all clients advertise
  support for version 3.

### Acceptance criteria

1. **Metadata passthrough** – The raw metadata (`vrf_entries`, `witness_commitments`, etc.) is forwarded unchanged from the consensus certificate. Verified by the unit test
   `summarize_consensus_certificate_includes_bindings` in
   [`rpp/runtime/node.rs`](../../rpp/runtime/node.rs).
2. **Binding digests** – The new binding fields (`vrf_output`,
   `witness_commitment_root`, `quorum_bitmap`, …) match the Poseidon folds that the
   consensus circuit enforces. Also covered by
   `summarize_consensus_certificate_includes_bindings` and by the regression tests in
   [`tests/consensus/consensus_proof_integrity.rs`](../../tests/consensus/consensus_proof_integrity.rs).

When either criterion fails, the route returns `503 Service Unavailable` until the
runtime records a valid certificate again.
