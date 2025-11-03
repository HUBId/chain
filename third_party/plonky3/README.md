# Plonky3 vendored dependencies

The `third_party/plonky3/` tree mirrors the upstream Plonky3 crates consumed by
`prover/plonky3_backend`. Each crate is unpacked into `<crate>/<version-or-sha>/`
so multiple revisions can co-exist without collisions. Non-crate assets live at
fixed locations:

- `config.toml` – Cargo configuration snippet emitted by the vendor run.
- `manifest/checksums.json` – SHA-256 digest manifest covering every vendored
  file. Regenerate it alongside any refresh.

The automation that keeps this mirror in sync is documented in the
[Plonky3 mirroring workflow](../../docs/third_party/plonky3.md#mirroring-workflow).

## Refresh workflow

Run the helper script from the repository root to fetch and validate the
sources:

```shell
python3 scripts/vendor_plonky3/refresh.py --write-checksums
```

The command performs the following steps:

1. Cleans stale files in `third_party/plonky3/` (preserving the README and
   `manifest/`).
2. Executes `cargo vendor --versioned-dirs` using the manifest at
   `scripts/vendor_plonky3/Cargo.toml` so crates are written to
   `<crate>/<version>/` directories.
3. Writes the generated Cargo configuration to `third_party/plonky3/config.toml`.
4. Computes SHA-256 digests for every file in the vendor tree and, when invoked
   with `--write-checksums`, replaces `manifest/checksums.json` with the new
   hashes.
5. Exits with a non-zero status if the computed hashes differ from the recorded
   manifest and `--write-checksums` was not supplied.

Use the following environment variables to customise the workflow when needed:

| Variable | Purpose | Default |
| --- | --- | --- |
| `PLONKY3_VENDOR_MANIFEST` | Alternate manifest to feed into `cargo vendor`. | `scripts/vendor_plonky3/Cargo.toml` |
| `PLONKY3_VENDOR_DIR` | Destination directory for the vendored crates. | `third_party/plonky3/` |
| `PLONKY3_VENDOR_CONFIG` | Output path for the generated Cargo config snippet. | `third_party/plonky3/config.toml` |
| `PLONKY3_VENDOR_CHECKSUMS` | Location of the checksum manifest. | `third_party/plonky3/manifest/checksums.json` |

Once the mirror is updated, run the script again with `--check-only` to validate
that no uncommitted changes remain:

```shell
python3 scripts/vendor_plonky3/refresh.py --check-only
```

Commit the refreshed crates, updated checksums, and any config changes together
so the checksum gate remains deterministic.
