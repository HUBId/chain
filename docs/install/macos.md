# macOS installation guide

macOS releases ship both `.pkg` installers and signed `.dmg` images that embed
the same CLI/GUI binaries as Linux. Follow these steps to keep gatekeeper and
change-control evidence aligned.

## 1. Verify release signatures

1. Download the macOS artifact (`rpp-wallet-<version>-macos-<arch>-<features>.pkg`
   or `.dmg`) plus the release `SHA256SUMS.txt`, signature, and certificate
   bundle.【F:docs/wallet_release_workflow.md†L27-L45】
2. Verify `SHA256SUMS.txt` with cosign and compare the artifact checksum with
   `sha256sum -c SHA256SUMS.txt` on a trusted host.
3. Record the notarization status (Gatekeeper prompt or `spctl --assess` output)
   alongside the checksum log before proceeding.

## 2. Install the package or disk image

* `.pkg`: double-click the installer, review the hooks summarized in
  [`INSTALL.wallet.md`](../../INSTALL.wallet.md), and allow the post-install
  script to place binaries, docs, and hooks under `/usr/local` plus the GUI
  bundle under `/Applications`.【F:INSTALL.wallet.md†L25-L38】
* `.dmg`: mount the image, drag `rpp-wallet-gui.app` into `/Applications`, copy
  the `config/` directory to `~/Library/Application Support/rpp-wallet/` or
  `/etc/rpp-wallet/`, and run `hooks/postinstall.sh` to register CLI PATH
  entries.【F:INSTALL.wallet.md†L25-L38】

The post-install hook also prints the `docs/INSTALL.md` path so operators can
capture it for audit logs.

## 3. Configure RPC, GUI, and security settings

1. Edit `~/Library/Application Support/rpp-wallet/wallet.toml` (or `/etc/rpp-wallet/wallet.toml`
   for multi-user machines) and configure `[wallet.rpc]`, `[wallet.gui]`, and the
   Phase 4 security sections before launching the GUI.【F:config/wallet.toml†L15-L41】【F:config/wallet.toml†L61-L85】【F:docs/wallet_phase4_advanced.md†L124-L158】
2. If mTLS/RBAC is enabled, store certificates in the per-user Keychain or
   `/usr/local/etc/rpp-wallet/certs` and point the config at those paths. Restart
   the runtime so the TLS context reloads.
3. Document screenshots of the GUI tabs the first time you unlock the wallet on
   a host, following the callouts in the training guide (Send, Receive, and Node
   tabs are required for compliance evidence).【F:docs/training/wallet_operator_training.md†L58-L140】
4. Turn on proof enforcement and lifecycle controls before distributing the app:
   * Set `[wallet.prover].backend = "stwo"` plus `require_proof = true` and
     `allow_broadcast_without_proof = false` to keep sends fail-closed; restart
     the GUI/runtime after editing because live reload is unavailable.【F:config/wallet.toml†L1-L3】【F:config/wallet.toml†L125-L132】
   * Tune `[wallet.rescan]` for your lookback window and note the `chunk_size`
     in the rollout ticket so operators can replay history deterministically.【F:config/wallet.toml†L95-L102】
   * Use `scripts/run_hybrid_mode.sh` when staging hybrid demos so `/health/*`
     probes align with the GUI lifecycle.【F:scripts/run_hybrid_mode.sh†L1-L55】

5. Attach the lightweight GUI wireframes to the deployment log (one per tab):

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

## 4. Post-install validation

1. Launch `rpp-node wallet --config /path/to/wallet.toml --log-level debug` from
   Terminal to confirm readiness probes pass before relying on the LaunchServices
   registration. Health endpoints mirror the Linux workflow.
2. Use `Console.app` or `tail -f ~/Library/Logs/rpp-wallet.log` to ensure mTLS and
   RBAC logs are present when you toggle security features.
3. Attach GUI screenshots and the readiness check output to the deployment
   record, then hand off to the [wallet operations](../operations/wallet.md) team
   for log shipping and rotation.

## 5. Uninstall path

1. Run `hooks/uninstall.sh` to remove PATH entries and LaunchServices caches as
   documented in the install manifest.【F:INSTALL.wallet.md†L30-L38】
2. Delete `/Applications/rpp-wallet-gui.app` and `/usr/local/bin/rpp-wallet*`
   binaries.
3. Retain `~/Library/Application Support/rpp-wallet/` until backups are rotated
   or exported per the operations runbook.
