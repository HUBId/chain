# WORM Export Runbook

## Overview
The validator streams signed admission policy audit entries to an append-only
write-once-read-many (WORM) target for off-site retention. Operators can route
exports either through the bundled `tools/worm-export` wrapper (used for local
smoke testing) or to an S3-compatible object store with object-lock retention.

## Prerequisites
- Admission policy signing must be enabled so that each exported entry carries a
  verifiable signature.
- Configure the WORM export endpoint and retention settings in
  `network.admission.worm_export` within the validator configuration.
- Ensure the target object store (or wrapper) is reachable from the validator
  nodes and is provisioned with object-lock retention enabled when using S3.

## Enabling WORM Export
1. Update the validator configuration:
   ```toml
   [network.admission.worm_export]
   enabled = true
   required = true
   retention_days = 90
   retention_mode = "compliance"
   require_signatures = true

   [network.admission.worm_export.target]
   kind = "s3"
   endpoint = "https://worm-compatible.example.com"
   region = "us-west-2"
   bucket = "validator-audit"
   prefix = "admission-audit"
   access_key = "..."
   secret_key = "..."
   ```
2. Restart the validator runtime. Startup will fail fast if the WORM target or
   credentials are misconfigured when `required = true`.

## Verification Steps
1. Append a test policy change via the admission API (or perform a controlled
   allowlist update). Confirm the local audit log records the entry.
2. Inspect the WORM target for a new object whose name matches the
   `<timestamp>-<id>.json` convention. Validate that the payload matches the
   local audit entry and that the signature field is present.
3. For S3 targets, check the object metadata to confirm
   `x-amz-object-lock-mode` and `x-amz-object-lock-retain-until-date` are set to
   the expected values based on the configured retention window.
4. Run the automated smoke test to verify the export pipeline end-to-end:
   ```bash
   cargo xtask test-worm-export
   ```
   The check exercises the bundled wrapper and asserts that retention metadata
   is propagated correctly.

## Troubleshooting
- **Startup failure with `worm export` errors:** ensure the configuration
  contains a `target` section when `enabled = true`. Missing credentials or
  unreachable endpoints are surfaced through the runtime bootstrap logs.
- **Unsigned entry rejected:** the exporter requires signatures when
  `require_signatures = true`. Verify admission signing is enabled and the
  configured key is active.
- **Retention metadata missing in object store:** double-check that the bucket
  has object-lock enabled and that the credentials permit setting retention
  headers.
