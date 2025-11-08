# WORM Export Wrapper

This helper script simulates an append-only write-once-read-many (WORM) backend by
materialising each payload as a standalone JSON object on disk. It is intended for
local development and continuous integration smoke tests.

The runtime streams signed admission audit entries through this wrapper when the
`command` export target is configured. The script honours the following environment
variables, which are populated by the runtime exporter implementation:

- `WORM_EXPORT_ROOT` – directory for emitted JSON artefacts and retention metadata.
- `WORM_EXPORT_OBJECT` – suggested object name (`<timestamp>-<id>.json` by default).
- `WORM_RETENTION_MIN_DAYS`, `WORM_RETENTION_MAX_DAYS`, `WORM_RETENTION_MODE` –
  retention policy hints propagated to the external storage provider.
- `WORM_RETAIN_UNTIL` – RFC3339 timestamp after which the object may be eligible for
  deletion, computed from the configured retention policy.

A `retention.meta` file is written alongside the exported object to make it trivial
for the smoke tests to assert that retention information is forwarded correctly.
