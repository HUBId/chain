# Plonky3 setup artifacts

The JSON fixtures in this directory capture the official Plonky3 proving and
verifying keys for each circuit that the backend wires into the node. They are
generated either by invoking the upstream key generator directly or by
serialising pre-built artifacts produced by that toolchain.

## Regenerating artifacts

From the repository root run the helper script, pointing it at the generator or
an artifact directory that already contains the `*.vk`/`*.pk` binaries emitted by
Plonky3:

```shell
# Invoke the generator for every circuit (placeholders are shell-escaped).
python3 scripts/generate_plonky3_artifacts.py \
  --generator 'plonky3-keygen --circuit {circuit} --vk {verifying_key} --pk {proving_key}' \
  --generator-cwd /path/to/plonky3/toolchain \
  --pretty \
  config/plonky3/setup

# Or ingest pre-built key material from disk.
python3 scripts/generate_plonky3_artifacts.py \
  --artifact-dir /path/to/key/outputs \
  --pretty \
  config/plonky3/setup
```

The script materialises one `*.json` document per circuit containing a
`verifying_key` and `proving_key` descriptor. Each descriptor follows the JSON
schema returned by `plonky3_backend::VerifyingKey::json_schema()` and
`plonky3_backend::ProvingKey::json_schema()` and includes:

- `encoding`: the inline representation of the payload (currently always
  `base64`).
- `value`: the base64 payload, optionally wrapping compressed bytes.
- `byte_length`: length of the decoded key material in bytes.
- `compression`: present when compression was applied (the helper defaults to
  `gzip`, use `none` for raw base64).
- `hash_blake3` (optional): a diagnostic digest emitted when the Python
  `blake3` module is available.

Custom tooling can call the backend helpers
`plonky3_backend::VerifyingKey::from_encoded_parts` and
`plonky3_backend::ProvingKey::from_encoded_parts` to validate the descriptors,
including gzip decompression and BLAKE3 hash verification.

By default the script gzip-compresses the binary key material before encoding it
as base64 so the files remain manageable. The Rust loader in
`rpp/proofs/plonky3/crypto.rs` transparently decompresses the payloads based on
the `compression` field, so no additional steps are required when the node
starts.

Use `--compression none` if you need uncompressed base64 output (for example,
when diffing against upstream snapshots).
