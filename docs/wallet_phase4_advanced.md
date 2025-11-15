# Wallet Phase 4 – Advanced Operations

Phase 4 extends the RPP wallet with enterprise-focused controls: encrypted backup and
recovery formats, watch-only projections, multisig signing hooks, Zero State Import (ZSI)
workflows, hardened RPC security (mTLS and RBAC), and hardware signing bridges. This
document covers configuration, migrations, operational runbooks, and troubleshooting.
Pair it with the [Wallet Operator Runbook](./wallet_operator_runbook.md), which details the
prerequisite validation and acceptance testing sequence that proves each feature works end
to end before a release is promoted.

## Backup/Recovery Formats and Rotation

Phase 4 introduces deterministic, chunked backup archives for wallet state. Operators can
export encrypted snapshots via `rpp-wallet backup export` or schedule automatic exports by
setting `wallet.backup.auto_export_enabled = true` in `config/wallet.toml`. Archives are
AES-GCM encrypted and metadata is stored alongside Argon2id-derived passphrase profiles to
block weak phrases.

* **Storage layout** – Each backup lands in `wallet.backup.export_dir` with the pattern
  `<wallet-id>-<timestamp>.rppb`. Metadata (`manifest.json`) records the schema version,
  checksum tree, and passphrase policy applied.
* **Rotation** – The runtime prunes old artifacts once `wallet.backup.max_generations` is
  exceeded. Keep at least three generations and replicate the directory to offline media.
* **Recovery** – Import with `rpp-wallet backup restore --path <archive>`. The tool verifies
  the checksum, passphrase policy, and schema version before decrypting. Use
  `--skip-passphrase-policy` only for lab environments; production restores must satisfy the
  configured policy.
* **Passphrase policies** – `wallet.backup.passphrase_profile` supports `argon2id`,
  `pbkdf2`, and `plaintext`. Only use `plaintext` for CI smoke tests. Rotate passphrases at
  least quarterly and maintain a dual-control register.

### Troubleshooting Backups

* **Checksum mismatch** – Re-export after verifying disk health; failing hardware often
  produces mismatched checksums. Confirm `verify_checksums` is enabled when importing a ZSI
  bundle to avoid cascading corruption.
* **Passphrase rejection** – Ensure the passphrase meets the current profile; Argon2id
  requires at least 12 characters with mixed classes. Update the profile only after
  confirming all operators can satisfy the new complexity.

## Watch-Only Mode

Watch-only mode derives addresses from an extended public key while omitting private
material. Enable it by setting `wallet.watch_only.enabled = true` and pointing
`wallet.watch_only.xpub_path` at an exported xpub file generated via
`rpp-wallet keys export-xpub`.

* **RPC exposure** – Keep `wallet.watch_only.expose_rpc = false` until downstream services
  are ready to consume the read-only projection. When true, watch-only accounts appear in
  `wallet_listAccounts` responses with the `watch_only` flag.
* **Operational use** – Deploy watch-only instances on monitoring hosts to reconcile
deposits without risking spend keys.
* **Security** – Treat xpub files as sensitive. They do not enable spending but can leak
transaction graph metadata if exposed.

### Troubleshooting Watch-Only

* **Missing derivations** – Confirm the birthday height via `wallet.engine.birthday_height`
and re-run `rpp-wallet rescan --from-height <height>` if early transactions are absent.
* **RPC not showing accounts** – Ensure RBAC policies grant the `read_state` role to the
requesting client when role enforcement is active.

## Multisig Hooks

The wallet exposes multisignature flows only when the binary is compiled with the
`wallet_multisig_hooks` feature. Builds without the feature omit the CLI commands and
JSON-RPC methods, and any runtime access returns `WalletError::MultisigDisabled`.

Set `[wallet.multisig].enabled = true` in the wallet configuration to opt in after
compiling with the feature. When active, use the CLI helpers to manage state:

* `rpp-wallet multisig scope get|set|clear` – inspect or update the active threshold scope.
* `rpp-wallet multisig cosigners list|set|clear` – manage the local cosigner registry.
* `rpp-wallet multisig export --draft <id>` – export draft metadata for external
  coordinators.

Hook integration remains environment-specific. Deployments can continue to implement
scripts under `scripts/multisig/` that broker PSBT signing with their chosen coordinator.
Ensure those scripts are only enabled when `[wallet.multisig].enabled` is true and the
binary was produced with `wallet_multisig_hooks`.

### Multisig Troubleshooting

* **Feature disabled errors** – Ensure the runtime was built with `wallet_multisig_hooks`
  and that `[wallet.multisig].enabled = true`. Otherwise the CLI hides multisig commands and
  RPC calls surface `wallet multisig support disabled at build time`.
* **Stalled approvals** – Check coordinator logs for quorum mismatches. Use
  `rpp-wallet multisig scope get` and `rpp-wallet multisig cosigners list` to inspect the
  recorded policy and cosigners.
* **Hook errors** – Ensure the hook process has executable permissions and returns JSON in
  the expected schema; malformed responses surface as runtime errors during multisig export
  or signing.

## ZSI Workflows

Zero State Import provides a fast bootstrap from vetted snapshots.

1. Stage the bundle in `wallet.zsi.bundle_path` and verify signatures with
   `rpp-wallet zsi verify --bundle <path>`.
2. Enable the feature by setting `wallet.zsi.enabled = true` and restart the runtime.
3. Import via `rpp-wallet zsi import --bundle <path>`. The tool confirms checksums when
   `wallet.zsi.verify_checksums = true`.
4. Disable `wallet.zsi.enabled` after import to prevent inadvertent replays.

### ZSI Troubleshooting

* **Checksum mismatch** – Redownload the bundle and confirm the CA certificate chain matches
  the publisher’s. Partial downloads produce truncated archives.
* **Schema mismatch** – Upgrade the wallet runtime and database to the required schema via
  the migration guidance below before retrying.

## RPC Security (mTLS and RBAC)

Phase 4 hardens the JSON-RPC surface with optional mutual TLS and role-based access
controls. Configure `[wallet.rpc.security]` and `[wallet.security]` together.

* **mTLS** – Set `wallet.rpc.security.mtls_required = true` and populate
  `wallet.rpc.security.trusted_ca_dir` with PEM-encoded issuing CAs. Server certificates are
  loaded from `wallet.rpc.security.certificate` and `wallet.rpc.security.private_key`.
* **RBAC** – Enable `wallet.rpc.security.role_enforcement = true` and map client identities
  to roles in the `role_bindings_path` file. Roles include `admin`, `read_state`, and
  `submit_tx`. Use `rpp-wallet rbac lint` to validate the file.
* **Legacy compatibility** – Leave both flags false to retain Phase 3 behaviour. Clients must
  negotiate TLS even when mTLS is disabled because the server certificate is still loaded.
* **Build flag** – The node binary now ships the TLS stack behind the `rpp-chain` feature
  `wallet_rpc_mtls`. Enable it (`cargo build -p rpp-chain --features wallet_rpc_mtls`) when you
  need wallet RPC mTLS.

### Certificate Management

* Maintain an offline CA that issues short-lived certificates (30–90 days).
* Automate rotation with a cron job that calls `rpp-wallet cert renew` and reloads the
  runtime.
* Store private keys with `0600` permissions and rotate immediately after suspected
  compromise.

### RPC Troubleshooting

* **Handshake failures** – Inspect the wallet log for `tls::Error`. Mismatched CA chains or
  expired certificates are the most common cause.
* **Unauthorized responses** – Verify the client certificate fingerprint is bound to the
  correct roles and that `wallet.auth.enabled` is not conflicting with RBAC policies.

## Hardware Integration

The wallet can delegate signing to hardware devices, such as Ledger or FIDO-based HSMs.

* **Transport** – `wallet.hw.transport` supports `hid`, `usb`, and `tcp`. HID is the safest
  default because it requires direct device access.
* **Device selector** – Set `wallet.hw.device_selector` to a vendor/product ID pair (e.g.
  `"2c97:4018"`) or a device serial. Leave null to prompt during CLI usage.
* **Fallback** – Keep `wallet.hw.fallback_to_software = true` so unattended jobs can still
  sign with the software key if the hardware device disconnects. For high-assurance
  environments, set to false and monitor for `HardwareFallback` events.

### Hardware Troubleshooting

* **Device not detected** – Confirm OS-level permissions allow HID access. On Linux, install
  the provided udev rules and replug the device.
* **Stalled signing** – Ensure the hardware firmware version meets the minimum specified in
  release notes. Ledger devices require blind signing to be enabled for PSBT flows.

## Feature Flags

Phase 4 introduces the following cargo feature flags in addition to the prover and GUI flags
from earlier phases:

* `runtime` (enabled by default) – Builds the wallet runtime, JSON-RPC service, and
  background tasks required for `[wallet.*]` sections.
* `backup` (enabled by default) – Includes backup CLI commands and hashing dependencies for
  archive metadata.
* `wallet_multisig_hooks` – Compiles multisig hooks, telemetry, and RPC surfaces; required
  when `[wallet.multisig].enabled = true`.
* `wallet_zsi` – Adds ZSI import/export logic and CLI commands.
* `wallet_rpc_mtls` – Enables the mTLS/RBAC middleware as well as GUI and CLI security
  controls.
* `wallet_hw` – Includes hardware signing traits and device backends.
* `wallet_gui` – Compiles the iced GUI frontend.

Watch-only projections and backup schedules are controlled solely through configuration
(`[wallet.watch_only]`, `[wallet.backup]`); there are no `wallet_watch_only` or
`wallet_backup` cargo features.

Combine these with prover flags as needed. CI runs `cargo xtask test-wallet-feature-matrix`
to execute `cargo check`/`cargo test` for the default wallet build, each individual feature,
and the "all wallet features" combination. Use the same xtask locally to reproduce coverage
failures.

## Migration Guidance

1. **Schema readiness** – Ensure `WalletStore::schema_version()` returns at least 4 after
   updating the binary. Run `rpp-wallet migrate` to apply the new buckets for backups,
   security registries, and multisig metadata.
2. **Configuration** – Extend `config/wallet.toml` with the new sections introduced in this
   document. Safe defaults keep advanced features disabled until explicitly enabled.
3. **Certificate staging** – Generate server/client certificates and populate the
   `wallet.rpc.security` paths before switching on mTLS.
4. **Backup seeding** – Take a manual backup using the new format before enabling automatic
   exports so rollback points exist if issues arise.
5. **Hardware pilot** – Test hardware signing in a staging environment before allowing
   production spends. Monitor for `HardwareSession` events.
6. **Documentation refresh** – Update operator runbooks with the troubleshooting and security
   considerations listed in this guide and follow the [Wallet Operator Runbook](./wallet_operator_runbook.md)
   so each migration captures acceptance evidence alongside the schema/config diffs.

## Security Considerations

* Enforce strong passphrases and track custody via dual control logs.
* Rotate certificates and keys on a fixed cadence; never reuse TLS private keys across
  environments.
* Harden the host OS with full disk encryption and ensure backups inherit the same controls.
* Audit RBAC bindings quarterly and expire unused roles.

## Operator Checklist

* [ ] Apply database migrations and verify schema version 4.
* [ ] Update configuration with Phase 4 sections and confirm defaults.
* [ ] Stage certificates and enforce mTLS/RBAC if required.
* [ ] Pilot backup exports and test restore drills quarterly.
* [ ] Decide on watch-only deployments and configure xpub distribution.
* [ ] Integrate multisig hooks and hardware devices in staging before production rollout.
