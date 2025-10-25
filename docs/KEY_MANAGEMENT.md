# Key management

Firewood validators rely on verifiable random function (VRF) keypairs to
participate in consensus and submit uptime proofs. This guide documents the
lifecycle for those keys across supported secrets backends and the
operator-facing tooling bundled with the runtime.

## Secrets backends and storage

Validator configurations declare a `vrf_key_path` and the backing secrets
backend. The default template uses filesystem storage but Vault is also
supported; the HSM backend is intentionally disabled at build time until the
hardware integration is finished.【F:config/validator.toml†L1-L48】【F:rpp/runtime/config.rs†L36-L177】

| Backend | Description | Operational notes |
| --- | --- | --- |
| `filesystem` | Stores the VRF keypair alongside other node secrets. | The runtime creates parent directories on startup and expects the host to lock down file permissions (`600`/`700`).【F:rpp/runtime/config.rs†L82-L117】 |
| `vault` | Reads and writes the VRF keypair to a Vault KV path. | Empty identifiers are rejected; ensure the configured path resolves to an existing KV secret engine before launch.【F:rpp/runtime/config.rs†L130-L160】 |
| `hsm` | Placeholder for future hardware-backed keys. | Not available in current builds; configuring it returns a validation error so operators must provision filesystem or Vault instead.【F:rpp/runtime/config.rs†L58-L177】 |

All backends expose a unified `DynVrfKeyStore` interface so runtime components
(such as the validator RPC handlers) can load, rotate, or export key material
without branching on backend specifics.【F:rpp/runtime/config.rs†L40-L82】

## Lifecycle operations

Use the `rpp-node validator vrf` commands to manage keys without editing files
manually:

- `rpp-node validator vrf rotate` generates a new keypair, persists it via the
  configured secrets backend, and prints the public key for audit trails.
- `rpp-node validator vrf inspect` loads the stored keypair and displays both the
  public and secret components for verification.
- `rpp-node validator vrf export --output <path>` writes the keypair as JSON and
  can feed external backup workflows.【F:rpp/node/src/main.rs†L54-L199】

All commands accept `--config` to point at non-default validator configuration
files. The CLI reuses `RuntimeOptions`, meaning secrets-related overrides (for
example, `--data-dir` or telemetry tokens) remain available during rotation or
inspection flows.【F:rpp/node/src/main.rs†L38-L115】【F:rpp/node/src/lib.rs†L143-L216】

## Validation and enforcement

During runtime bootstrap the configuration loader ensures the chosen secrets
backend is valid for the provided `vrf_key_path`, creates directories when
necessary, and surfaces actionable errors instead of proceeding with missing
keys. Vault integrations must provide non-empty identifiers and pass backend
self-validation before the runtime starts.【F:rpp/node/src/lib.rs†L993-L1080】【F:rpp/runtime/config.rs†L82-L177】

Validator telemetry and RPC endpoints rely on the VRF key to generate proofs. If
rotation happens while the runtime is offline, restart the process to load the
new material; when using Vault, the runtime fetches secrets on demand and will
begin signing with the rotated key at the next request.【F:rpp/runtime/config.rs†L56-L110】【F:rpp/rpc/api.rs†L960-L1047】

For governance expectations on storing backups, escrow arrangements, and audit
logging, see [`GOVERNANCE.md`](GOVERNANCE.md). Threat modelling guidance lives in
[`THREAT_MODEL.md`](THREAT_MODEL.md).
