# Zero Sync Identity Lifecycle

The wallet exposes a set of helpers that operators can use to manage Zero Sync
identities locally.  The flows live in `rpp_wallet::zsi::lifecycle` and cover
the full lifecycle: issuing a new identity, rotating its public-key
commitment, revoking compromised credentials and auditing the registry entry.
Each operation returns a [`LifecycleReceipt`](../../rpp/wallet/src/zsi/lifecycle.rs)
that records the derived registry state and, when the active prover backend
supports it, an optional lifecycle proof.

## Command-line helpers

`rpp_wallet::cli::zsi` integrates the lifecycle routines with `clap` so they
can be triggered from the wallet CLI.  Operators issue or rotate identities by
providing the wallet address, the current genesis identifier and optional
consensus approvals:

```text
$ wallet zsi issue \
    --identity alice \
    --genesis-id genesis-1 \
    --attestation "proof-bytes" \
    --approval validator-1:deadbeef:42

$ wallet zsi rotate \
    --identity alice \
    --previous-genesis genesis-1 \
    --previous-attestation "proof-bytes" \
    --next-genesis genesis-2
```

The CLI returns the lifecycle receipt as JSON so it can be persisted or fed
into external tooling.

## JSON-RPC wrappers

`rpp_wallet::rpc::zsi` mirrors the CLI surface for services that prefer a
JSON-RPC interface.  Each handler receives a `*_Params` structure and returns
the same `LifecycleReceipt` as the library API, making it straightforward to
build dashboards or automation on top of the lifecycle data.

## Receipts and proofs

The wallet records a `LifecycleProof` whenever the configured prover backend
implements the STWO identity API.  The proof captures the backend name,
operation and compact digests of the witness and proof payloads, allowing
external systems to reason about the lifecycle transition without having to
inspect raw artefacts.

The integration tests in [`tests/zsi/lifecycle_flow.rs`](../../tests/zsi/lifecycle_flow.rs)
exercise the library, CLI and RPC pathways to ensure all entry points emit
consistent receipts.
