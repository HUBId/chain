# RPP vendor refresh procedure

> **Scope:** Step-by-step checklist for updating the vendored `rpp-stark`
> backend inside the chain workspace. Follow it whenever upstream publishes a
> new commit or vector bundle so that the imported sources stay reproducible and
> CI keeps enforcing the proof invariants.

## Prerequisites

- Local checkout of the `chain` repository with write access.
- The upstream `rpp-stark` repository cloned or reachable over Git. The
  examples below assume SSH access to `git@github.com:ava-labs/rpp-stark.git`;
  substitute the remote if you use HTTPS.
- Rust toolchain pinned in `rust-toolchain.toml` (`1.79`) plus the nightly
  version referenced by the upstream workspace for regenerating vectors.
- Python 3 for checksum tooling under `scripts/`.

## 1. Pull the upstream commit

1. Add (or update) the remote:

   ```bash
   git remote get-url rpp-stark >/dev/null 2>&1 || \
     git remote add rpp-stark git@github.com:ava-labs/rpp-stark.git
   git fetch rpp-stark --tags
   ```

2. Inspect the upstream history and choose the commit you want to vendor:

   ```bash
   git log rpp-stark/main --oneline | head
   ```

3. Populate `vendor/rpp-stark` with the chosen revision. Using `git archive`
   keeps the workspace clean and matches how CI runs offline:

   ```bash
   upstream_ref=rpp-stark/<branch-or-tag-or-commit>
   rm -rf vendor/rpp-stark
   git archive --format=tar --prefix=vendor/rpp-stark/ "${upstream_ref}" | \
     tar xf -
   ```

4. Record the vendored revision in your commit message and update
   `vendor/rpp-stark/CHANGELOG.md` or `RELEASE_NOTES.md` if upstream requires a
   note for downstream consumers.

## 2. Refresh deterministic vectors

1. Run the exporter test inside the vendor workspace to regenerate the mini
   bundle and confirm it is deterministic:

   ```bash
   cargo test -p rpp-stark --locked --test golden_vector_export \
     -- --nocapture export_and_verify_golden_vectors
   ```

   The harness writes into `vendor/rpp-stark/vectors/stwo/mini/` and aborts if
   regenerated artefacts differ from the repository baseline.

2. If the upstream commit introduces new fixtures, review the diff under
   `vendor/rpp-stark/vectors/` and update the accompanying README files so the
   provenance is documented.

## 3. Verify vector checksums

1. Generate a checksum manifest for every vector artefact (hex and binary):

   ```bash
   scripts/checksums.sh --output \
     vendor/rpp-stark/vectors/stwo/mini/checksums.sha256 \
     vendor/rpp-stark/vectors/stwo/mini/*
   ```

2. Validate the manifest before committing:

   ```bash
   scripts/verify_checksums.sh \
     --manifest vendor/rpp-stark/vectors/stwo/mini/checksums.sha256
   ```

   Both scripts rely on `sha256sum`; they fail if any artefact diverges from
   the recorded digest.

3. Golden-vector regression tests now emit a concise checksum ledger for the
   STWO mini bundle at `logs/rpp_golden_vector_checksums.log` whenever they run
   with `--features backend-rpp-stark`. CI archives the `logs/` directory, so
   you can diff two runs locally for drift:

   ```bash
   diff -u logs/rpp_golden_vector_checksums.log \
     /path/to/previous/run/logs/rpp_golden_vector_checksums.log
   ```

    The backend unit-suite job now compares the emitted ledger (checksums plus
    proof-size/stage metadata) against the checked-in baseline at
    `tests/baselines/rpp_golden_vector_checksums.log` and fails the run on
    mismatches. After intentionally regenerating vendor vectors or touching the
    verifier telemetry format, refresh the baseline via:

   ```bash
   tools/update_rpp_golden_vector_baseline.sh
   ```

    Include the resulting diff in your vendor-refresh PR so reviewers can audit
    the new digests, proof length, and stage metadata.

## 4. Run interoperability tests

Execute the workspace-level interop harness to ensure the updated vendor tree
is compatible with the chain verifier:

```bash
cargo test --locked --features backend-rpp-stark --test interop_rpp_stark \
  -- --nocapture
```

The test loads the STWO golden vector bundle, rebuilds transcripts, and checks
stage flags end-to-end.

## 5. Exercise the expanded fail-matrix suite

Cover every negative scenario so regression signals remain stable:

```bash
cargo test -p rpp-chain --locked --features backend-rpp-stark \
  --test rpp_fail_matrix -- --nocapture
```

This wrapper reuses the vendor fixtures in `vendor/rpp-stark/tests/fail_matrix/`
for serialization, Merkle, and FRI tampering cases.

## 6. Update Cargo metadata and lockfiles

1. Ensure the vendored crate metadata resolves with the rest of the workspace:

   ```bash
   cargo metadata --locked --format-version 1 \
     > logs/vendor_cargo_metadata_$(date +%Y%m%d).log
   ```

2. Double-check the main binaries still compile against the refreshed vendor
   tree:

   ```bash
   cargo check --locked -p rpp-chain -p rpp-node \
     --features backend-rpp-stark
   ```

3. If the upstream release bumps dependency versions, regenerate
   `Cargo.lock` from the workspace root and re-run the metadata check. Keep the
   resulting log alongside the PR for audit purposes.

## 7. Final review checklist

- [ ] `vendor/rpp-stark` reflects the intended upstream commit and contains no
      stray build artefacts.
- [ ] Golden vectors and checksum manifests are up to date.
- [ ] Interop and fail-matrix tests pass with `--locked`.
- [ ] `cargo metadata` and `cargo check` succeed with the backend feature
      enabled.
- [ ] Release notes and documentation reference the refreshed vendor bundle.

Escalate to the release engineering channel if any step fails, especially when
checksum verification or fail-matrix coverage uncovers unexpected changes.
