# RPP Wallet for macOS

This README accompanies the `.pkg` and `.dmg` artifacts.

1. Validate the release manifest with cosign, then notarization status with
   `spctl --assess` before trusting the installer.
2. Follow the [macOS installation guide](docs/install/macos.md) to copy configs
   into `~/Library/Application Support/rpp-wallet/`, run the provided hooks, and
   document GUI screenshots for every host.
3. Align runtime operations with [`docs/operations/wallet.md`](docs/operations/wallet.md)
   and keep the incident response links from [`docs/troubleshooting/wallet.md`](docs/troubleshooting/wallet.md)
   handy for on-call responders.
4. The bundled `docs/INSTALL.md` details every post-install and uninstall script
   executed by the package, so auditors can trace the modifications.
