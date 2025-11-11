# ZSI Renewal Request Fixtures

This directory stores the JSON fixtures consumed by the ZSI renewal tests.  In
particular, `renewal_request.json` contains a fully attested
`AttestedIdentityRequest` that exercises the end-to-end renewal flow under
realistic consensus and proof constraints.

## File layout: `renewal_request.json`

The fixture mirrors the Rust type
[`AttestedIdentityRequest`](../../../rpp/runtime/types/identity.rs).  It is a
single JSON object with the following top-level sections:

- `declaration`: An `IdentityDeclaration` that bundles the proving artefacts
  for the claimant.  Inside it, the nested `genesis` block captures the public
  key, derived address, VRF material, observed state/identity roots, initial
  reputation, and the Merkle commitment proof required to prove the slot was
  vacant.  The accompanying `proof` block contains the Blake2s commitment and
  STARK payload (`ChainProof::Stwo`) attesting to the identity circuit.
- `attested_votes`: An array of `SignedBftVote` entries representing the quorum
  of pre-commit votes that authorised the renewal at a specific block height.
  Each vote bundles the BFT vote metadata together with the Ed25519 signature.
- `gossip_confirmations`: The list of validator addresses that rebroadcasted
  the attestation, ensuring it satisfied the minimum gossip requirements.

The tests load the fixture through `tests/support/zsi.rs` and assert both the
cryptographic integrity and the ledger height encoded inside the JSON.

## Regenerating the fixture

Regenerate the JSON by running the workspace helper:

```shell
cargo run --features prover-stwo -p zsi-fixtures
```

The repository pins a nightly toolchain in `rust-toolchain.toml`, so make sure
that toolchain is installed before running the command (e.g. `rustup toolchain
install nightly`).  The generator emits human-readable JSON to
`tests/vectors/zsi/renewal_request.json` and logs the absolute path on success.

After updating the fixture, commit the refreshed JSON to the repository so that
continuous integration uses the same test vectors and avoids drift.
