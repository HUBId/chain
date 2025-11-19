# RPP Wallet for Windows

Use this README when installing the `.zip` or `.msi` wallet packages.

1. Verify the cosign-signed `SHA256SUMS.txt` manifest and record `signtool
   verify /pa` output (for MSI) or Authenticode details before continuing.
2. Follow the [Windows installation guide](docs/install/windows.md) to run the
   PowerShell hooks, configure `%ProgramData%\rpp-wallet\wallet.toml`, and capture
   GUI screenshots for your change log.
3. Keep [`docs/operations/wallet.md`](docs/operations/wallet.md) and
   [`docs/troubleshooting/wallet.md`](docs/troubleshooting/wallet.md) nearby so
   RPC, backup, and error-code procedures are always available to responders.
4. See `docs/INSTALL.md` for a verbatim list of the install/uninstall actions
   performed by the scripts bundled with each artifact.
