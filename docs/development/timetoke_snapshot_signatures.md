# Timetoke snapshot signatures

Timetoke snapshot manifests are now signed before they are exposed to the gossip/state-sync
pipeline. The signing flow relies on the [`ed25519_dalek::SigningKey`] that each node loads (or
bootstraps) via [`NodeConfig::load_or_generate_timetoke_snapshot_signing_key`]. The resulting
manifest bytes are canonical JSON—identical to what downstream tooling already consumes—and the
Ed25519 signature is encoded as base64 for transport and storage.

## Where signatures are produced

* `TimetokeSnapshotProducer::publish` signs the canonical manifest bytes and stores both payload and
  signature in the `SnapshotStore`. Callers receive a `TimetokeSnapshotHandle` whose
  `signature: Option<String>` field contains the base64 signature so they can persist it alongside
  the manifest.
* Persisting components must write the JSON manifest and a sibling `<file>.sig`
  text file containing the base64 signature. Empty or missing signature files
  are treated as fatal errors by the runtime.
* Runtime state sync and other snapshot readers surface the stored signature
  through `SnapshotStore::signature`. Consumers expect a value and propagate I/O
  errors if the signature cannot be read or decoded.

## Key management

* The node configuration exposes `timetoke_snapshot_key_path`, defaulting to `./keys/timetoke_snapshot.toml`.
  `ensure_directories` guarantees the parent directory exists and `load_or_generate_timetoke_snapshot_signing_key`
  writes a TOML structure containing the hex-encoded 32-byte secret and (optional) public key.
* Keys are generated with `rand::rngs::OsRng`, matching the rest of the Ed25519 usage in the codebase.
  Existing deployments can drop a pre-generated keypair at the configured path; validation checks that
  the declared public key matches the secret.

## Verifying signatures manually

```rust
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};

let manifest_bytes = std::fs::read("manifest.json")?;
let signature_b64 = std::fs::read_to_string("manifest.json.sig")?;
let signature = Signature::from_bytes(&BASE64.decode(signature_b64.trim().as_bytes())?)?;
let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
verifying_key.verify(&manifest_bytes, &signature)?;
```

This mirrors the assertions in `tests/consensus/timetoke_snapshots.rs` and lets operators audit the
artifacts they receive via state sync or direct file transfer.

## Legacy compatibility

Legacy manifests without signatures are no longer supported. Operators must
retrofit `.sig` files when migrating archives; otherwise state sync fails with a
`snapshot signature missing` error as soon as the runtime loads the payload.
