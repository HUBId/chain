# Windows installation guide

Windows bundles ship as `.zip` payloads plus WiX-based `.msi` installers. Both
paths use the same signed binaries, hooks, and documentation described below.

## 1. Verify release signatures

1. Download the Windows bundle (`rpp-wallet-<version>-windows-<arch>-<features>.zip`
   or `.msi`) and the release `SHA256SUMS.txt` + cosign metadata.
2. Validate the manifest with cosign and then run PowerShell `Get-FileHash -Algorithm SHA256 <artifact>`
   to confirm it matches the manifest entry before unzipping or running the MSI.【F:docs/wallet_release_workflow.md†L27-L45】
3. Record `signtool verify /pa <msi>` output (for MSI) or the Authenticode
   signature details in your change ticket.

## 2. Install the payload

*Zip workflow*

1. Extract the `.zip` into `C:\Program Files\RPP Wallet\<version>`.
2. Launch an elevated PowerShell prompt and run `hooks\install.ps1` to add PATH
   entries and register the GUI shortcut documented in
   [`INSTALL.wallet.md`](../../INSTALL.wallet.md).【F:INSTALL.wallet.md†L25-L33】

*MSI workflow*

1. Double-click the `.msi` or run `msiexec /i rpp-wallet-<version>-windows-<arch>-<features>.msi`.
2. The installer embeds the same hooks as `install.ps1`, so PATH updates and
   Start Menu shortcuts are applied automatically.

## 3. Configure RPC, GUI, and security

1. Copy `config/wallet.toml` to `%ProgramData%\rpp-wallet\wallet.toml` (or a
   per-user folder) and edit `[wallet.rpc]`, `[wallet.gui]`, and
   `[wallet.rpc.security]` to match your deployment.【F:config/wallet.toml†L15-L41】【F:config/wallet.toml†L61-L85】
2. Store certificates/keys referenced by the security sections under
   `%ProgramData%\rpp-wallet\certs` with ACLs restricting access to the wallet
   service account. Follow the Phase 4 guide for mTLS/RBAC wiring and `rpp-wallet
   rbac lint` pre-flight checks.【F:docs/wallet_phase4_advanced.md†L124-L158】
3. Launch `rpp-wallet-gui.exe`, unlock the keystore, and capture screenshots of
   the History, Send, Receive, and Node tabs for the deployment log using the
   training callouts as a reference.【F:docs/training/wallet_operator_training.md†L58-L140】
4. Enforce proof and lifecycle controls before releasing the MSI/zip to users:
   * Set `[wallet.prover].backend = "stwo"`, `require_proof = true`, and
     `allow_broadcast_without_proof = false` so sends remain fail-closed; restart
     the Windows service or GUI after editing because live reload is disabled.【F:config/wallet.toml†L1-L3】【F:config/wallet.toml†L125-L132】
   * Update `[wallet.rescan]` with your retention window and record `chunk_size`
     alongside the rollout ticket so reschedules are deterministic.【F:config/wallet.toml†L95-L102】
   * Use `scripts\run_hybrid_mode.sh` from WSL (or PowerShell via Git Bash) when
     staging hybrid demos so `/health/*` probes remain aligned with the GUI lifecycle.【F:scripts/run_hybrid_mode.sh†L1-L55】

5. Add lightweight GUI wireframes to the deployment record (one per tab):

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

## 4. Health checks and GUI validation

1. Run `scripts\run_wallet_mode.sh` from WSL or `rpp-node.exe wallet --config ...`
   from PowerShell to confirm the readiness endpoints respond before leaving the
   service unattended.【F:scripts/run_wallet_mode.sh†L1-L47】
2. Use `Invoke-WebRequest http://127.0.0.1:9090/health/live` to verify the RPC
   host binding and confirm firewall rules allow local probes.
3. Point operators to the [wallet operations](../operations/wallet.md) and
   [troubleshooting](../troubleshooting/wallet.md) docs when handing off the
   deployment so log locations, backup paths, and error codes remain visible.

## 5. Uninstall path

1. Zip-based installs: run `hooks\uninstall.ps1` as Administrator to remove PATH
   entries and shortcuts, then delete `C:\Program Files\RPP Wallet\<version>`.
2. MSI installs: use `Apps & Features` or `msiexec /x <msi>`; the uninstall hook
   matches the PowerShell script in [`INSTALL.wallet.md`](../../INSTALL.wallet.md).【F:INSTALL.wallet.md†L25-L33】
3. Preserve `%ProgramData%\rpp-wallet\` until backups are archived and the
   [operations runbook](../operations/wallet.md) confirms retention windows are
   met.
