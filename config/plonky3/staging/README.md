# Plonky3 staging artifacts

The upstream Plonky3 toolchain emits binary proving (`.pk`) and verifying (`.vk`) key
files. GitHub's review tooling rejects pull requests that include opaque binary blobs,
so the artifacts in this directory are base64-encoded text files with a `.b64`
suffix. Each file contains the raw, **uncompressed** key bytes encoded on a single
line plus a trailing newline for POSIX compatibility.

The helper script `scripts/generate_plonky3_artifacts.py` automatically detects both
plain binary inputs and these base64 wrappers, so contributors can run it without
extra flags:

```sh
python3 scripts/generate_plonky3_artifacts.py \
  --artifact-dir config/plonky3/staging \
  --pretty \
  --signature-output config/plonky3/setup/manifest.json \
  config/plonky3/setup
```

To refresh the base64 files after generating new keys, re-encode them manually with
`base64 -w0 <file> > <file>.b64` (or an equivalent tool). The important thing is that
the decoded bytes match the raw outputs produced by `plonky3-keygen`.
