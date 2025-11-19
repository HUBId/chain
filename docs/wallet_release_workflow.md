# Wallet release workflow

This workflow stitches together the wallet bundle and installer builders so
operators can produce reproducible artifacts across Linux, Windows, and macOS.

## Prerequisites

* Install the platform packaging tools:
  * Linux: `cargo-deb`, `cargo-rpm`, `dpkg-deb`, and `rpmbuild`.
  * Windows: `cargo-wix` plus the WiX toolset and `signtool` access.
  * macOS: `cargo-bundle`, Xcode command line tools, `pkgbuild`, and `hdiutil`.
* Ensure the wallet binaries compile with the desired feature set by running
  `cargo xtask test-wallet-feature-matrix`.
* Set `SOURCE_DATE_EPOCH` or run the builders via `scripts/repro_check.sh` to
  verify the artifacts are reproducible.

## Building the artifacts

1. Build the base binaries with `scripts/build_release.sh` using the desired
   target triple. Pass `--wallet-version <semver>` to enable the wallet builders.
2. The script invokes `cargo xtask wallet-bundle` and
   `cargo xtask wallet-installer` for the target, storing the outputs under
   `dist/wallet/<target>/`.
3. Each artifact follows the `rpp-wallet-<version>-<os>-<arch>-<features>` naming
   pattern and contains the README, LICENSE, and INSTALL docs plus the
   platform-specific hooks.
4. Checksums are generated next to every artifact (`.sha256` files).

The installers depend on the common wallet bundle code path so the binaries,
configs, and manifest stay consistent regardless of the OS/arch matrix.
