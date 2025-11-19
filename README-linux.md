# RPP Wallet for Linux

Use this README when installing the signed Linux tarball, `.deb`, or `.rpm`
artifacts.

1. Verify the cosign-signed `SHA256SUMS.txt` manifest and the per-artifact
   checksums before extracting a payload.
2. Follow the [Linux installation guide](docs/install/linux.md) to run the
   provided hooks, stage `/etc/rpp-wallet/wallet.toml`, and capture GUI/RPC
   evidence for change control.
3. Review [`docs/operations/wallet.md`](docs/operations/wallet.md) for logging,
   backup rotation, and telemetry requirements, then mirror the error handling
   flows in [`docs/troubleshooting/wallet.md`](docs/troubleshooting/wallet.md)
   when incidents occur.
4. Reference `docs/INSTALL.md` inside the bundle for the precise post-install and
   uninstall hooks executed by each package type.
