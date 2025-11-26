# Upgrade runbook

Use this runbook when upgrading binaries or configuration schemas. Execute it after reviewing the
release notes referenced in the repository root.

| Symptom | Check | Action |
| --- | --- | --- |
| Upgrade fails with `config_version ... is not supported` | Review the CLI output or dry-run logs to see whether the node or Malachite configs rejected the version string.【F:rpp/runtime/config.rs†L979-L990】【F:rpp/runtime/config.rs†L185-L203】 | Update `config_version` to the supported value (`1.0` for node, `1.0.0` for Malachite) and merge any new fields from the template before retrying the upgrade.【F:config/node.toml†L1-L20】【F:config/malachite.toml†L1-L32】 |
| Telemetry requirements changed between releases | Compare the template defaults shipped with the new release (telemetry enabled in hybrid/validator) with your local overrides.【F:config/hybrid.toml†L41-L46】【F:config/validator.toml†L41-L45】 | If the release increases telemetry cadence or requires authentication, update the runtime CLI flags (`--telemetry-endpoint`, `--telemetry-auth-token`, `--telemetry-sample-interval`) or the `rollout.telemetry` block and perform a dry run to validate.【F:rpp/node/src/lib.rs†L1045-L1080】【F:rpp/node/src/lib.rs†L258-L359】 |
| VRF key material incompatible with new secrets backend | Use `cargo run -p rpp-chain -- validator vrf inspect` to confirm the backend and identifier detected by the runtime.【F:rpp/node/src/main.rs†L57-L178】 | If migrating to Vault or a new filesystem path, adjust the `secrets.backend` block and rerun the CLI rotation (`validator vrf rotate`) to reprovision keys before starting the upgraded runtime.【F:rpp/runtime/config.rs†L34-L123】 |

Document the outcome in the [operator checklist](../checklists/operator.md) and proceed to the
[startup runbook](startup.md) for post-upgrade validation.

## Upgrade compatibility expectations

Mixed-version windows are supported only for the duration of a rollout. When staging a deploy:

- Run `cargo xtask test-integration` so the `upgrade_compat` flow exercises mixed-version
  nodes and wallets, verifies signing across proof backends, and checks mempool RPC responses for
  backwards-compatible fields and deprecation warnings.
- Keep legacy wallets configured to accept proof-less drafts only while the upgraded nodes are still
  permissive; once the proof version bump lands, require proofs before lifting maintenance gates.
- Confirm mempool telemetry still reports `min_fee_rate` and queue weights even when older nodes
  advertise trimmed payloads; treat missing fields as a deprecation warning and schedule cleanup
  before the next release train.

