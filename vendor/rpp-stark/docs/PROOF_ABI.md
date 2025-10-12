# Proof ABI quick reference

The proof envelope is versioned via `PROOF_VERSION` (see
[`src/proof/types.rs`](../src/proof/types.rs)) and is frozen to guarantee byte
compatibility with existing verifiers. Any change to the byte layout requires a
`PROOF_VERSION` bump, updated snapshots and a changelog entry.

## Envelope layout (v1)

```
+----------------------+----------------------------------------------------+
| Field                | Description                                        |
+======================+====================================================+
| u16 proof_version    | Must equal `PROOF_VERSION` (currently `1`).        |
| [u8;32] params_hash  | Hash of the parameter profile used by the prover.  |
| [u8;32] public_digest| Digest of the canonical public inputs.             |
| Digest trace_commit  | Merkle root of the trace openings.                 |
| u8 has_comp          | `1` if a composition commitment follows.           |
| Digest comp_commit?  | Optional Merkle root for the composition openings. |
| FriProof fri         | Versioned FRI proof structure (`ser/` encoding).    |
| Openings openings    | Trace/composition opening bundles.                 |
| u8 has_telemetry     | `1` if telemetry data follows.                     |
| Telemetry telemetry? | Optional telemetry frame (`total_bytes`, stats).    |
+----------------------+----------------------------------------------------+
```

All integers use little-endian encoding. Digest fields are raw byte strings; the
proof format does not reinterpret their endianness.

## Transcript ordering

Verifiers reconstruct the Fiat–Shamir transcript strictly in this order:

1. `params_hash`
2. Protocol tag and seed from the parameter profile
3. `public_digest`
4. `trace_commit`
5. Optional `comp_commit`
6. Each FRI layer root (`fri.roots`)
7. Fold challenges and query schedule as dictated by `FriProof`

All sampled challenges (α vector, out-of-domain points, query indices) must be
reproducible from the transcript alone; proofs never carry pre-sampled
challenges.

## Openings structure

The openings block is composed of:

- `trace` – indices, leaves and authentication paths for the execution trace.
- `composition` – optional bundle aligned with the FRI composition queries.
- `aux` – optional auxiliary openings carrying additional witness data.

Each bundle serializes as counts (`u32`), sorted indices (`u32`), leaf bytes and
Merkle paths. Indices must be unique and sorted in ascending order.

## Telemetry frame

When present, telemetry records:

- The serialized proof length in bytes
- Declared FRI security parameters (query budget, cap size, cap degree)
- Optional profiling counters used by CI reporting

Telemetry is ignored by the verifier logic but must be well-formed when
`has_telemetry = 1`.
