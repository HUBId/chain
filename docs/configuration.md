# Configuration guide

This document explains how runtime profiles resolve configuration files, the schema and secrets
controls enforced by the loaders, and how to dry-run changes before deploying. See
[modes](modes.md) for per-profile behaviour and the operator [checklist](checklists/operator.md) for
rollout tasks.

## Precedence and discovery

1. **Command-line overrides:** `--config` flags passed to the node or wallet CLI take priority and are
   wired through `RuntimeOptions` into the loader.【F:rpp/node/src/lib.rs†L194-L238】【F:rpp/node/src/lib.rs†L993-L1007】
2. **Environment override:** If no CLI path is provided, the loader consults `RPP_CONFIG` and trims
   empty values.【F:rpp/node/src/lib.rs†L1010-L1031】
3. **Mode defaults:** Fallback templates are selected per runtime mode: `config/node.toml`,
   `config/hybrid.toml`, `config/validator.toml`, or `config/wallet.toml` as appropriate.【F:rpp/runtime/mod.rs†L35-L47】【F:rpp/node/src/lib.rs†L993-L1007】
4. **Adjacent blueprints:** When a node config loads, the runtime also pulls in the sibling
   `malachite.toml` (defaulting to the template in `config/`).【F:rpp/runtime/config.rs†L1329-L1335】【F:rpp/runtime/config.rs†L164-L185】【F:config/malachite.toml†L1-L40】

The loader records the source (CLI, environment, default) alongside the parsed TOML so later conflict
checks can emit precise error messages.【F:rpp/node/src/lib.rs†L960-L1007】

## Template catalogue

The repository ships profile-specific templates under `config/` for quick bootstrapping.【F:config/node.toml†L1-L33】【F:config/hybrid.toml†L1-L52】

* `config/node.toml` – single-role node defaults with telemetry disabled and RPC on 7070.【F:config/node.toml†L1-L37】
* `config/hybrid.toml` – combined node+wallet profile enabling telemetry and tuning gossip/heartbeat
  parameters.【F:config/hybrid.toml†L1-L47】
* `config/validator.toml` – validator-specific adjustments (testnet channel, faster heartbeats,
  telemetry enabled).【F:config/validator.toml†L1-L46】
* `config/wallet.toml` – wallet RPC at 9090 with remote gossip endpoints and Electrs disabled by
  default.【F:config/wallet.toml†L1-L27】
* `config/malachite.toml` – example consensus blueprint referenced by the node loader.【F:config/malachite.toml†L1-L32】

Copy one of these files, adjust local paths, and point the CLI to the new location for reproducible
configuration reviews.

## Schema and version validation

* **Node configuration:** `NodeConfig::validate` enforces `config_version`, non-zero runtime limits,
  telemetry field correctness, and P2P/secrets validation. Violations return configuration errors that
  map to exit code 2.【F:rpp/runtime/config.rs†L979-L1054】【F:rpp/node/src/lib.rs†L48-L120】
* **Malachite blueprint:** `MalachiteConfig::validate` checks that `config_version` satisfies the
  `>=1.0.0,<2.0.0` requirement before validating nested sections.【F:rpp/runtime/config.rs†L185-L210】
* **Wallet configuration:** Wallet profiles ensure gossip endpoints are provided when the embedded
  node is disabled and verify Electrs feature combinations when enabled.【F:rpp/runtime/config.rs†L1468-L1539】

Treat validation errors as actionable hints—the exact field name is embedded in each message.

## Secrets handling

Validators rely on the `secrets` block to manage VRF key material. The runtime supports filesystem and
Vault backends (HSM is stubbed out in this build) and automatically derives identifiers, creates
parent directories, and loads or generates keypairs through the configured backend.【F:rpp/runtime/config.rs†L34-L120】 CLI VRF subcommands reuse this configuration for rotation/inspection.【F:rpp/node/src/main.rs†L57-L178】

* Filesystem backends resolve relative paths under the configured directory and create missing parent
  folders.【F:rpp/runtime/config.rs†L117-L123】
* Vault backends require non-empty logical paths and validate the remote connection settings before
  use.【F:rpp/runtime/config.rs†L97-L114】

Use the wallet or validator templates as references for placing `vrf_key_path` alongside the secrets
backend.

## Dry runs and configuration generation

Passing `--dry-run` skips spawning the runtime and instead executes configuration loading, override
application, port-conflict checks, and telemetry initialisation inside the main task. Successful dry
runs emit a `dry run completed` log with resolved sources so operators can verify configuration origin
without binding to network ports.【F:rpp/node/src/lib.rs†L258-L359】 Adding `--write-config` persists the
resolved node configuration to disk for auditing.【F:rpp/node/src/lib.rs†L229-L355】

## Port collision remediation

Hybrid and validator modes must dedicate distinct RPC listeners for the node and wallet. The loader compares
addresses after parsing both configs and surfaces actionable errors when sockets overlap or when the
wallet RPC collides with the node P2P listener. Update one of the templates (or override on the CLI)
so the RPC ports no longer reuse the same TCP binding.【F:rpp/node/src/lib.rs†L722-L775】

For more operational guidance, consult the [startup runbook](runbooks/startup.md) and the
[observability runbook](runbooks/observability.md).

