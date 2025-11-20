# Linux installation guide

The Linux wallet bundle ships tarballs, `.deb`, and `.rpm` installers so host images
can reuse the same signed payloads regardless of packaging preference.
Pair these steps with the wallet operations and troubleshooting guides after
the binaries land on disk.

## 1. Verify release signatures

1. Download the bundle (`rpp-wallet-<version>-linux-<arch>-<features>.*`) plus
   the `SHA256SUMS.txt`, `.sig`, and `.pem` files that the release workflow
   publishes with every wallet build.【F:docs/wallet_release_workflow.md†L27-L45】
2. Verify the manifest signature with cosign:
   ```sh
   cosign verify-blob \
     --signature SHA256SUMS.txt.sig \
     --certificate SHA256SUMS.txt.pem \
     --certificate-identity https://github.com/rpp-chain/ztate \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     SHA256SUMS.txt
   ```
3. Confirm the artifact hash matches the manifest: `sha256sum -c SHA256SUMS.txt`.
4. Compare the build hash and feature tags recorded in the operator ticket with
   the bundle filename so you know the staged binary matches the signed
   artefact.

## 2. Install the bundle

*Tarball path*

1. Extract the tarball under `/opt/rpp-wallet/<version>` and review the staged
   `docs/INSTALL.md` file for the hook summary described in
   [`INSTALL.wallet.md`](../../INSTALL.wallet.md).【F:INSTALL.wallet.md†L1-L38】
2. Copy the configs from `config/` to `/etc/rpp-wallet/` (or your preferred
   config root) and set file permissions to `0640`/`0600` for private keys.
3. Run `hooks/postinstall.sh` as root to register PATH entries and the
   `rpp-wallet-rpc` systemd unit. Enable the service via `systemctl enable --now
   rpp-wallet-rpc.service`.

*Package managers*

* `.deb`: `sudo dpkg -i rpp-wallet-<version>-linux-<arch>-<features>.deb`
* `.rpm`: `sudo rpm -i rpp-wallet-<version>-linux-<arch>-<features>.rpm`

The package post-install script mirrors the tarball hook (symlinks, systemd
reload, service enable) so no extra steps are required.【F:INSTALL.wallet.md†L1-L24】

## 3. Configure RPC and GUI defaults

Edit `/etc/rpp-wallet/wallet.toml` after installation:

1. Bind the RPC host/port in `[wallet.rpc]` and decide whether the GUI should be
   available on the host by enabling `[wallet.gui]`.【F:config/wallet.toml†L15-L41】【F:config/wallet.toml†L61-L85】
2. Enable mTLS/RBAC when you are ready to enforce authenticated RPC access by
   populating `[wallet.rpc.security]` and `[wallet.security]` with the
   certificate paths and role bindings documented in the Phase 4 security guide.【F:docs/wallet_phase4_advanced.md†L124-L158】
3. For GUI rollouts, update the monitoring ticket with screenshots of the Send
   and Receive tabs following the textual overlays in the training guide so
   reviewers can compare the rendered components with the documented state.【F:docs/training/wallet_operator_training.md†L58-L110】
4. Enforce proof and lifecycle policies before handing the host to operators:
   * Set `[wallet.prover].backend = "stwo"`, `require_proof = true`, and
     `allow_broadcast_without_proof = false` for fail-closed sends; restart the
     service after editing because live reload is disabled.【F:config/wallet.toml†L1-L3】【F:config/wallet.toml†L125-L132】
   * Pin `[wallet.rescan]` to your lookback window and log the chosen
     `chunk_size` in the deployment ticket so reschedules stay predictable.【F:config/wallet.toml†L95-L102】
   * Use `scripts/run_hybrid_mode.sh` when staging hybrid node+wallet rollouts so
     readiness probes align with the wallet lifecycle controls.【F:scripts/run_hybrid_mode.sh†L1-L55】

5. Attach lightweight GUI wireframes to the change record for acceptance (one
   snapshot per tab):

   ```
   +---------------------------+    +---------------------------+
   | Overview                  |    | Receive                   |
   | Sync: height 12345  ✔     |    | Address: wallet1...       |
   | Balances: confirmed 1.2   |    | [Copy] [New address]      |
   | Pending ops: 0            |    | Tooltip: rotate per use   |
   | [Refresh] [Rescan]        |    +---------------------------+
   +---------------------------+

   +---------------------------+    +---------------------------+
   | Send                      |    | Prover                    |
   | To: [_____________]       |    | Queue: 0 pending          |
   | Amount: [______] sats     |    | Backend: STWO (required)  |
   | Fee slider [---|----]     |    | [Retry] [View logs]       |
   | Proof: STWO (required)    |    | Progress table rows       |
   | [Preview] [Sign] [Send]   |    +---------------------------+
   | Error banner slot         |
   +---------------------------+
   ```

Restart the wallet service after changing the configuration because live reload
is not supported.【F:config/wallet.toml†L1-L3】

## 4. Post-install health checks

1. Use `scripts/run_wallet_mode.sh` during staging to confirm the binaries pass
   the `/health/live` and `/health/ready` probes before enabling the service in
   production.【F:scripts/run_wallet_mode.sh†L1-L47】
2. Capture `curl http://127.0.0.1:9090/health/ready` output and attach it to the
   change ticket. Pair it with a GUI screenshot once the wallet auto-locks to
   prove `[wallet.gui].auto_lock_secs` works as expected.【F:config/wallet.toml†L61-L74】
3. Link the deployment ticket to the [wallet operations](../operations/wallet.md)
   and [troubleshooting](../troubleshooting/wallet.md) guides so on-call staff
   know where to find RPC, logging, and error-code references.

## 5. Uninstall path

1. Stop the service: `systemctl disable --now rpp-wallet-rpc.service`.
2. Run `hooks/prerm.sh` from the installation directory to remove the PATH
   entries and systemd links before deleting `/opt/rpp-wallet/<version>` or
   uninstalling the package.【F:INSTALL.wallet.md†L16-L24】
3. Remove `/etc/rpp-wallet/` only after archiving backups and keystores per the
   operations guide.
