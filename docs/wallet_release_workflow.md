# Wallet release workflow

This workflow stitches together the wallet bundle and installer builders so
operators can produce reproducible artifacts across Linux, Windows, and macOS.
Pair it with the [wallet release checklist](release_checklist.md) to ensure the
manual smoke tests and governance gates are captured alongside the artifacts.

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
   pattern and contains the LICENSE, INSTALL docs, the repository README, and the
   OS-specific `README-<os>.md` alongside the platform hooks and configs.
4. Checksums are generated next to every artifact (`.sha256` files).

## SBOM, checksums, and provenance

The GitHub release workflow extends these builders by generating and publishing
additional wallet-specific metadata:

1. `cargo cyclonedx` runs for the CLI (`rpp-wallet`) and GUI (`rpp-wallet-gui`)
   crates and writes SBOMs under `dist/artifacts/wallet/sbom-*.json`.
2. `scripts/checksums.sh` produces `dist/artifacts/wallet/SHA256SUMS.txt` covering
   the bundle, installers, manifests, and SBOMs. The workflow signs the manifest
   with cosign (`SHA256SUMS.txt.sig`/`.pem`) before uploading artifacts.
3. Each artifact is paired with provenance metadata produced by
   `scripts/provenance_attest.sh`, resulting in `.intoto.jsonl`, `.sig`, and `.pem`
   files that capture the builder ID and hash. These statements are attached to
   every release alongside the artifacts so auditors can verify the supply-chain
   evidence.【F:.github/workflows/release.yml†L200-L350】【F:.github/workflows/release.yml†L350-L470】

The installers depend on the common wallet bundle code path so the binaries,
configs, and manifest stay consistent regardless of the OS/arch matrix.
