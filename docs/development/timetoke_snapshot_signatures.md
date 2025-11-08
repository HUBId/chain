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
* Persisting components should write the JSON manifest as usual and create a sibling
  `<file>.sig` text file containing the base64 signature. Empty signature files should not be
  created; omit the `.sig` when the handle reports `None`.
* Runtime state sync and other snapshot readers surface the stored signature through
  `SnapshotStore::signature`. The `.sig` companion is optional during the migration—missing files
  trigger a warning (`TODO(ENG-4972)`) but the manifest is still served so legacy stores remain
  consumable.

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

State sync warns once per snapshot root when the companion `.sig` file is missing, but continues to
serve the payload. This fallback is temporary—tracked under `TODO(ENG-4972)`—and lets existing
snapshot archives remain valid while the new signatures propagate through the network.
