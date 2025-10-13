# Malachite MSRV Vendor Directory

This directory holds MSRV-compatible vendor sources for the following Malachite subcrates:

- `malachite`
- `malachite-base`
- `malachite-nz`
- `malachite-q`

## Regenerating `malachite-base`

The vendored sources for `malachite-base` are tracked under `vendor/malachite-msrv/malachite-base/`.
To refresh them, install [`cargo-download`](https://crates.io/crates/cargo-download) if necessary and run:

```bash
scripts/vendor_malachite_base.sh
```

The script downloads version `0.4.18` of the crate, removes any stale placeholders, and syncs the
extracted sources into the vendor directory while pruning build artifacts.
