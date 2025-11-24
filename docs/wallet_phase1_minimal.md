# Wallet runtime configuration (phase 1)

> **Phase navigation:** Previous phase: _Foundational runtime bootstrap_ · Next
> phase: [Wallet Phase 2 – Policies & Prover Guide](wallet_phase2_policies_prover.md) ·
> [Wallet documentation index](README.md#wallet-documentation-index)
>
> **Sections:** [Policies](#policies) · [GUI](#gui) · [Backup](#backup) ·
> [Security](#security)

This document tracks the initial set of configuration options that the wallet
runtime exposes for early operators. The defaults in `config/wallet.toml` are
safe for local development, but production deployments should review the
following sections.

## Policies

- `wallet.engine`: controls the engine data directory, keystore bundle path,
  and optional birthday height for partial syncs.
- `wallet.policy`: defines address gap limits and confirmation requirements
  before funds are considered spendable.
- `wallet.fees`: sets minimum/maximum fee rate bounds together with the
  default value used by RPC helpers.
- `wallet.prover`: toggles prover enablement, selects the backend (`mock` or
  `stwo`), sets per-job timeouts, bounds witness sizes, caps concurrency, and
  controls whether proofs are required before broadcasts (fail-open vs.
  fail-closed modes).

Future phases expand on these sections with deployment playbooks and
component-specific tuning guidance. Phase 2 introduces persistent policy
snapshots, fee estimator automation, and prover selection—follow the navigation
links above when you are ready to upgrade.

## GUI

### Telemetry opt-in

The iced-based wallet GUI only publishes telemetry when operators explicitly
enable the opt-in flag. Add the following to the `[wallet.gui]` section of
`config/wallet.toml` (or the corresponding profile override) to turn on the
instruments:

```toml
[wallet.gui]
telemetry_opt_in = true
```

The same flag is persisted in the GUI preferences file
(`wallet-gui-settings.toml`) alongside theme and polling overrides.【F:rpp/wallet/src/config/wallet.rs†L200-L227】【F:rpp/wallet/src/ui/preferences.rs†L23-L71】
When enabled, the UI emits histogram and counter events—such as
`ui.rpc.latency_ms`, `ui.send.steps`, `ui.rescan.triggered`, and
`ui.errors.by_code`—through the workspace metrics facade. These signals remain
dormant whenever the opt-in is unset, ensuring no telemetry leaves the operator
workstation by default.【F:rpp/wallet/src/ui/telemetry.rs†L1-L220】

### CLI telemetry opt-in

Command-line workflows (backup management, watch-only toggles, hardware probes,
and Zero Sync helpers) share the same opt-in defaults. The CLI checks the
standard wallet configuration if it exists, and honours the environment
variable `RPP_WALLET_TELEMETRY_OPT_IN` (accepting `true/1/yes` and
`false/0/no`).【F:rpp/wallet/src/cli/telemetry.rs†L1-L154】 Operators can export
metrics for these flows by setting the flag before running a command:

```bash
export RPP_WALLET_TELEMETRY_OPT_IN=1
rpp-wallet backup export --rpc-endpoint http://127.0.0.1:9090
```

When enabled, the CLI records action counters—e.g. `cli.action.events` labelled
for backups, watch-only, hardware, and ZSI operations—only after each RPC or
proof task resolves, ensuring failures and successes are distinguished without
logging sensitive identifiers.【F:rpp/wallet/src/cli/telemetry.rs†L23-L148】【F:rpp/wallet/src/cli/wallet.rs†L1180-L1516】【F:rpp/wallet/src/cli/zsi.rs†L199-L244】

## Backup

Phase 1 focuses on stabilising the runtime surface; automated backups land in
[Phase 4](wallet_phase4_advanced.md#backuprecovery-formats-and-rotation). In the
interim, operators should take filesystem snapshots (or VM/volume-level backups)
after initial key import so manual recovery remains possible.

## Security

The Phase 1 runtime emphasises deterministic RPC behaviour and telemetry opt-in
controls so production deployments can pass early security reviews.

### JSON-RPC reference

### Transport, authentication, and limits

- The wallet runtime exposes a single JSON-RPC 2.0 endpoint at `/rpc`. Every
  request must include a valid `jsonrpc: "2.0"` header and method name; invalid
  payloads are rejected with a `-32700` *parse error* or a `-32600` *invalid
  request* response. Tokens configured under `wallet.auth` are only used for
  bearer verification and are never echoed back to callers. Rate-limit
  exhaustions return `-32061` and include `x-ratelimit-limit`,
  `x-ratelimit-remaining`, `x-ratelimit-reset`, and `retry-after` headers so
  callers can back off until the current minute window is replenished.
- Configure listener, optional CORS allow-list, and per-minute request budgets
  through `[wallet.rpc]` in `config/wallet.toml`. Operators can disable the
  limiter by leaving `requests_per_minute` unset, or pick a positive value to
  enable it. Additional RPC-specific budgets (transactions, prover, pipeline)
  are configured under `[wallet.budgets]` and enforced in the runtime.
- DTO schemas for every request/response are maintained in
  [`rpp/wallet/src/rpc/dto.rs`](../rpp/wallet/src/rpc/dto.rs).

### Error catalogue

| Code | Meaning | Typical triggers |
| ---- | ------- | ---------------- |
| `-32700` | Parse error | Malformed JSON payloads reaching the router |
| `-32600` | Invalid request | Unsupported JSON-RPC version or missing fields |
| `-32601` | Method not found | Calling an undefined method |
| `-32602` | Invalid params | Type/shape mismatches in `params` |
| `-32603` | Internal error | Serialization or poisoned state errors |
| `-32010` | Wallet error | Balance, UTXO, draft, or signing failures from the wallet engine |
| `-32020` | Sync error | Sync driver reported an error while handling the request |
| `-32030` | Node error | Execution node failures during broadcast |
| `-32040` | Draft not found | Signing/broadcasting an unknown draft |
| `-32041` | Draft unsigned | Broadcasting a draft before it is signed |
| `-32050` | Sync unavailable | `sync_status` / `rescan` requested without a configured sync coordinator |
| `-32051` | Rescan out of range | Historical rescan begins before the indexed height |
| `-32060` | Unauthorized | Missing or incorrect bearer token |
| `-32061` | Rate limited | Per-minute request quota exceeded |

Unless specified otherwise below, wallet engine failures surface as
`-32010 wallet error` responses. All errors omit secrets and authentication
material.

### Method catalogue

#### `get_balance`

- **Request**: `{}` (no parameters).
- **Response**: `{ confirmed, pending, total }` in satoshis.
- **Failures**: Wallet errors (e.g. storage access) propagate as `-32010`.

#### `list_utxos`

- **Request**: `{}` (no parameters).
- **Response**: `{ utxos: [{ txid, index, value, owner, timelock? }] }`.
- **Failures**: Wallet errors surface as `-32010`.

#### `list_txs`

- **Request**: `{}` (no parameters).
- **Response**: `{ entries: [{ txid, height, timestamp_ms, payload_bytes }] }`.
- **Failures**: Wallet errors surface as `-32010`.

#### `derive_address`

- **Request**: `{ change?: bool }`. Defaults to an external receive address.
- **Response**: `{ address }`.
- **Failures**: Wallet errors surface as `-32010`.

#### `create_tx`

- **Request**: `{ to, amount, fee_rate? }` in satoshis.
- **Response**: Draft metadata `{ draft_id, fee_rate, fee, total_input_value,
  total_output_value, spend_model, inputs[], outputs[] }`.
- **Failures**: Wallet engine errors (policy violations, insufficient funds)
  return `-32010`.

#### `sign_tx`

- **Request**: `{ draft_id }`.
- **Response**: Signing outcome `{ draft_id, signed: { tx_hex, proof_hex?,
  metadata: { backend, witness_bytes, prove_duration_ms, proof_required,
  proof_present, proof_bytes?, proof_hash? } }, locks }`.
- **Failures**: `-32040` if the draft does not exist, `-32010` for signing
  failures.

#### `broadcast`

- **Request**: `{ draft_id }`.
- **Response**: `{ draft_id, accepted }`.
- **Failures**: `-32040` if the draft does not exist, `-32041` if it has not
  been signed, node submission failures as `-32030`.

#### `policy_preview`

- **Request**: `{}`.
- **Response**: `{ min_confirmations, dust_limit }`.
- **Failures**: None expected under normal operation.

#### `sync_status`

- **Request**: `{}`.
- **Response**: `{ syncing, mode?, latest_height?, scanned_scripthashes?,
  pending_ranges?, checkpoints?, last_rescan_timestamp?, last_error? }`.
- **Failures**: `-32050` when no sync coordinator is configured.

#### `rescan`

- **Request**: `{ from_height }`.
- **Response**: `{ scheduled }` once the request is queued.
- **Failures**: `-32050` when sync is disabled, `-32051` if `from_height`
  predates the indexed range, sync errors as `-32020`.

## CLI quickstart

1. **Initialise wallet directories and keys**
   ```shell
   cargo run -p rpp-wallet -- init --keys-path ./keys/wallet.toml
   ```
   The command now prompts for a wallet passphrase and confirmation. Leave the
   prompt empty to use an empty passphrase or supply `--no-passphrase` to retain
   legacy plaintext files (primarily for development). Non-interactive
   deployments can provide credentials via `--passphrase-file <path>`,
   `--passphrase-env <VAR>`, or `--passphrase <value>`.

   Sample output:
   ```
   Wallet initialised successfully

     Data directory : ./data/wallet
     Keystore path   : ./data/wallet/keystore.toml
     Keys path       : ./keys/wallet.toml
     Public key      : <hex>
   ```

2. **Check sync status**
   ```shell
   cargo run -p rpp-wallet -- sync
   ```
   Sample output highlights syncing state, last scanned height, pending range,
   and any recent error.

3. **Derive a fresh receive address**
   ```shell
   cargo run -p rpp-wallet -- addr new
   ```
   Example output:
   ```
   Generated address

     Kind   : external
     Address: wallet1...
   ```

4. **End-to-end send flow**
   ```shell
   cargo run -p rpp-wallet -- send preview
   cargo run -p rpp-wallet -- send create --to wallet1... --amount 50000
   cargo run -p rpp-wallet -- send sign --draft-id <draft>
   cargo run -p rpp-wallet -- send broadcast --draft-id <draft>
   ```
   The create step prints draft inputs/outputs, `send sign` reports proof
   details, and `send broadcast` confirms acceptance.

5. **Trigger a historical rescan**
   ```shell
   cargo run -p rpp-wallet -- rescan --from-height 100_000
   ```
   The CLI confirms whether the job was scheduled before returning.

All commands honour the `--endpoint`, `--auth-token`, and `--timeout` flags, or
the `RPP_WALLET_RPC_*` environment variables.

## Encrypted keystore format

Wallet keys are now stored in a versioned TOML document that wraps the legacy
public/secret key pair in an authenticated ChaCha20-Poly1305 ciphertext. A new
Argon2id KDF (64 MiB memory, 3 iterations, single thread) derives the 256-bit
encryption key from the operator-supplied passphrase and a per-file random salt.
The keystore records the KDF parameters, salt, and AEAD nonce alongside the
ciphertext so future revisions can migrate in place.

When a plaintext keystore is encountered, the runtime automatically re-encrypts
it using the configured passphrase. Operators should rotate credentials by
re-running `wallet init --force` or updating the passphrase inputs before
copying the keystore to new hosts.

## Telemetry and budgets

- The runtime exports wallet-specific gauges and histograms:
  - `rpp.runtime.wallet.rpc_latency{method=...}` measures per-method latency for
    every wallet RPC (labels follow `WalletRpcMethod`).
  - `rpp.runtime.rpc.request.latency{method=...,result=...}` and
    `rpp.runtime.rpc.request.total{method=...,result=...}` aggregate results
    across wallet/proof/other handlers using the `result` label
    (`success|client_error|server_error`).
  - `rpp.runtime.wallet.runtime.active` and `rpp.runtime.wallet.sync.active`
    provide liveness samples for the runtime loop and sync driver.
- `wallet.budgets` define the per-minute submission budgets and maximum draft
  pipeline depth enforced at runtime. Keep these aligned with the rate-limits
  configured at the RPC layer to avoid surprising back-pressure.

## Related schema and configuration

- JSON-RPC DTOs: [`rpp/wallet/src/rpc/dto.rs`](../rpp/wallet/src/rpc/dto.rs)
- Runtime configuration template: [`config/wallet.toml`](../config/wallet.toml)

---

> **Phase navigation:** Previous phase: _Foundational runtime bootstrap_ · Next
> phase: [Wallet Phase 2 – Policies & Prover Guide](wallet_phase2_policies_prover.md) ·
> [Wallet documentation index](README.md#wallet-documentation-index)
