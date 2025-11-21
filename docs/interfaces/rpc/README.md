# RPC Interface Contracts

## API Versioning and Compatibility

RPP node and wallet RPC endpoints follow a semantic versioning policy that
mirrors the workspace release tags (`MAJOR.MINOR.PATCH`). Each RPC handler is
considered stable once it first ships in a minor release. Subsequent patch
releases may extend responses with new optional fields but never remove existing
keys, change value semantics, or reorder enumerations. Breaking a serialized
contract—such as removing a field or altering its type—requires a new major
version of the workspace and an explicit migration note.

We guarantee that clients compiled against a given `MAJOR.MINOR` release can
communicate with any server running the same `MAJOR` version for at least two
minor releases. For example, applications built against `1.8.x` continue to work
with servers up to and including `1.10.y`. After that window the API is still
expected to function, but previously deprecated fields may be removed in the
next minor bump.

## Deprecation Timeline

Every deprecation is announced one minor release in advance. The release notes
call out the affected field or endpoint, the intended removal version, and any
recommended migration steps. During the deprecation window the server continues
to populate the legacy payloads while emitting structured warnings via metrics
and logs so operators can monitor usage. Once the grace period expires (minimum
of two minor releases) the endpoint is either removed or the field becomes a no-
op entry, depending on the migration plan. Breaking removals only ship alongside
minor version bumps within the same major series.

## Semantic Version Mapping

* **Patch release (`MAJOR.MINOR.PATCH`)** – bug fixes only. Payload shapes and
  field semantics do not change.
* **Minor release (`MAJOR.MINOR`)** – may introduce new endpoints or add optional
  response fields. Deprecated fields announced previously may be dropped.
* **Major release (`MAJOR`)** – reserved for protocol overhauls that require
  coordinated client updates. All incompatible schema changes are bundled here.

Contract tests in `tests/rpc/` validate that representative request and response
examples remain compatible with the published JSON Schemas. CI executes these
checks on every PR so any incompatible change is caught before landing.

## Rate Limiting Semantics

The public RPC is protected by a per-IP token bucket. When a request depletes
the bucket and is throttled, the server responds with `429 Too Many Requests`
and the following headers:

* `X-RateLimit-Limit` – Maximum tokens in the bucket (the burst size).
* `X-RateLimit-Remaining` – Tokens still available for the current bucket.
* `X-RateLimit-Reset` – Seconds until a token is replenished and the bucket is
  usable again.

Clients should treat a `429` as a temporary condition. Retry only after waiting
for at least the advertised reset window and prefer exponential backoff to avoid
immediate re-throttling.

## Snapshot Regression Fixtures

Critical request/response shapes for the public RPC are captured as JSON fixtures
under `tests/rpc_snapshots/fixtures/`. The `rpc_snapshots` integration test sends
representative requests through the in-process router and compares the
serialization output against those snapshots.

* Run `cargo test -p rpp-chain --test rpc_snapshots` (or `make test:stable`) to
  confirm that local changes do not alter any canonical payloads.
* When an intentional contract change is required, bump the appropriate version
  constant in `tests/rpc_snapshots/mod.rs` and add a new `vN.json` fixture beside
  the prior version. Leave earlier fixtures in place so downstream clients can
  diff historical changes.
* Regenerate the fixtures by copying the `Actual snapshot` block printed by the
  failing test into the new `vN.json` file.

Document the version bump in the release notes alongside any schema updates so
consumers know to upgrade.

