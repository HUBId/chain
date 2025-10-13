# Malachite MSRV Vendor Directory

This directory holds MSRV-compatible vendor sources for the following Malachite subcrates:

- `malachite`
- `malachite-base`
- `malachite-nz`
- `malachite-q`

## Regenerating `malachite-base`

Vendored sources for `malachite-base` live under `vendor/malachite-msrv/malachite-base/`. The refresh
process is segmented to ensure we can audit each downloaded chunk and capture reproducible metadata.

### Prerequisites

Ensure `curl`, `tar`, `sha256sum`, `rsync`, and `python3` are available in your environment.

### Running the segmented workflow

Invoke the driver with the crate metadata, segment size (in bytes), a staging location, and the
destination vendor directory:

```bash
scripts/vendor_malachite_base.sh \
  malachite-base \
  0.4.18 \
  1048576 \
  storage-firewood/tmp \
  vendor/malachite-msrv/malachite-base
```

The script performs the following steps:

1. Resolve the canonical archive URL from crates.io and capture the published checksum.
2. Download the archive using fixed-size, sequential HTTP range requests
   (`malachite-base-0.4.18.part00`, `part01`, ...). Each segment is hashed immediately after
   download; failures trigger an automatic retry.
3. Append segment metadata (`index`, byte range, size, checksum, timestamp) to
   `vendor/malachite-msrv/malachite-base/manifest.json` after every successful download while
   streaming detailed logs to `vendor/malachite-msrv/logs/`.
4. Concatenate the verified segments, confirm the merged archive hash matches the checksum reported
   by crates.io, and abort the process if a mismatch is detected.
5. Extract the archive into an isolated staging directory, prune non-build artifacts (such as
   `.git`, `.github`, and `target/`), and synchronize the cleaned sources into the vendor directory.
6. Re-hash every extracted file, compare the digest with the bytes stored in the archive, and emit an
   `integrity-report.json` detailing the outcome for each path.

### Manifest format

`manifest.json` is rewritten on each run and contains:

- `crate`, `version`, `download_url`, and `chunk_size` used for the refresh.
- `expected_archive_sha256` (from crates.io) and `merged_archive_sha256` (calculated locally).
- `generated_at` and `completed_at` UTC timestamps.
- A `segments` array capturing the ordered list of downloaded ranges. Each entry records the byte
  range (`range_start` / `range_end`), size, segment checksum, and download timestamp.

`integrity-report.json` lists every extracted file along with the on-disk and in-archive sizes and
SHA-256 values, plus a `matches_archive` flag for quick verification.

To rerun the workflow, simply execute the command above with your desired chunk size and staging
directory. The script recreates the manifest, integrity report, and vendor contents from scratch on
each invocation.
