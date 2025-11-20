# Hardware vendor artifacts

This folder tracks the firmware and package manifests required to exercise
hardware-wallet integrations in staging. Each manifest records the vendor,
product, semantic version, package path, and a pinned SHA-256 digest that is
verified during the release checklist. The artifacts double as fixtures for the
`wallet_hw` acceptance matrix that covers unlocked (attested) devices.

## Included manifests

- `ledger_nano_firmware_v2.1.0.json` – PSBT-enabled Ledger Nano X firmware with
  blind-signing enabled once the device is unlocked.
- `trezor_suite_package_v24.12.1.json` – Trezor Suite/bridge bundle used to
  enable unlocked signing sessions for Model T devices.

When new vendor revisions are added, update the digest, stage the package under
`firmware/` or `packages/`, and link the change in the release checklist.

Signed, attested bundles can be generated with:

```
cargo xtask wallet-firmware --signing-key deploy/firmware/test_firmware_signing.key
```

The command copies each package referenced by the manifest, recalculates the
checksum, and emits a signed `attestation.json` alongside the manifest and
SHA256SUMS file for every vendor bundle.
