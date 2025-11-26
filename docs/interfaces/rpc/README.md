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

### Enforced deprecation windows

The RPC contract tests enforce the deprecation window so that removals never land
accidentally. When deprecating a field, add an entry to
`tests/rpc/deprecated_fields.toml` with the schema name, dotted property path,
the first workspace version that permits removal, and the expiry date of the
grace period. CI runs `deprecated_fields_require_version_bump_or_expiry` to
verify three rules:

1. Deprecated fields must stay in the JSON Schema until either the configured
   removal version ships or the expiry date is reached.
2. Allowlist entries with past-due expiry dates fail the build, prompting
   contributors to remove the field (and the allowlist entry) or extend the
   window with a new date.
3. Schema removals before the allowed version cause a failure unless the
   deprecation window has expired.

Document the new allowlist entry in release notes so client teams can plan the
migration and keep the `rationale` string up to date for reviewers.

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

The public RPC is protected by per-IP token buckets split into **read**
(`GET`/`HEAD`) and **write** (mutating) classes. Configure independent bursts
and replenish rates via `[network.limits.per_ip_token_bucket.read]` and
`[network.limits.per_ip_token_bucket.write]` in the node configuration; legacy
single-bucket configs map to both classes automatically.【F:config/node.toml†L37-L55】【F:rpp/runtime/config.rs†L1767-L1909】
When a request depletes the relevant bucket and is throttled, the server
responds with `429 Too Many Requests` and the following headers:

* `X-RateLimit-Limit` – Maximum tokens in the bucket (the burst size).
* `X-RateLimit-Remaining` – Tokens still available for the current bucket.
* `X-RateLimit-Reset` – Seconds until a token is replenished and the bucket is
  usable again.
* `X-RateLimit-Class` – The request class (`read` or `write`) that triggered the
  throttle.

The response body spells out the class as well (for example, `write rate limit
exceeded`). Clients should treat a `429` as a temporary condition. Retry only
after waiting for at least the advertised reset window and prefer exponential
backoff to avoid immediate re-throttling.

SDK-oriented helpers that parse the headers and clamp backoff are documented in
[`rpp/chain-cli/SDK.md`](../../../rpp/chain-cli/SDK.md); the code samples are
doctested so they stay aligned with the server’s token-bucket semantics.

### Wallet history pagination and rate limits

Wallet history endpoints (`/wallet/history` and the `history.page` JSON-RPC
shim used by the GUI) expose cursor tokens to page through cached entries. The
server stamps each page with `page_token`, `next_page_token`, and
`prev_page_token` values that can be echoed back to resume pagination even if a
previous call was throttled. Rate-limited responses still include the retry
headers above; once the `429` window elapses, clients should reuse the prior
token rather than restarting from the beginning. Backends (for example,
`rpp-stark` vs `plonky3`) and reorg-aware filters may adjust which entries are
returned, but stale tokens remain valid and simply yield an empty page if the
underlying history was truncated.

## Snapshot and state sync RPC errors

Snapshot operations expose structured error payloads. When a request fails the
response body always includes an `error` string and may also carry a
machine-readable `code` to simplify automation and runbook lookups. The
snapshot-related codes and their typical triggers are:

| Code | HTTP status | Typical message | Description |
| --- | --- | --- | --- |
| `state_sync_plan_invalid` | `400`/`404` | `chunk index <N> out of range (total <T>)`, `chunk <N> missing`, `invalid manifest` | The published snapshot plan or manifest does not match the requested chunk window. |
| `state_sync_metadata_mismatch` | `500` | `snapshot root mismatch: expected <expected>, found <actual>` | The local snapshot metadata (root or receipts) diverges from the advertised plan. |
| `state_sync_proof_encoding_invalid` | `503` | `failed to decode proof chunk` | Snapshot verification failed because the proof stream could not be decoded. |
| `state_sync_verification_incomplete` | `503` | `state sync verification failed` | The verifier stopped before producing a complete proof. |
| `state_sync_verifier_io` | `500` | `disk unavailable`, `ProofError::IO(...)` | I/O errors while reading snapshot chunks or verification inputs. |
| `state_sync_pipeline_error` | `500` | `snapshot store error: ...` | Internal orchestration errors while serving or verifying snapshot chunks. |
| `state_sync_pruner_state_error` | `500` | `pruner state unavailable` | Snapshot verification failed because pruning metadata was missing or inconsistent. |

The `/p2p/snapshots*` and `/state-sync/*` handlers surface these codes so
operators can map RPC responses directly to the remediation steps in the
troubleshooting guide.

### Consensus RPC errors

Consensus endpoints expose structured error payloads when finality or proof
verification fails. The `/consensus/proof/status` handler sets a `code` field in
addition to the human-readable `error` string:

| Code | HTTP status | Typical message | Description |
| --- | --- | --- | --- |
| `consensus_verifier_failed` | `503` | `invalid VRF proof`, `consensus certificate contains non-prevote in prevote set` | Consensus proof or binding verification failed. The runtime increments `rpp.runtime.consensus.rpc.failures{reason="verifier_failed"}` for observability. |
| `consensus_finality_unavailable` | `503` | `no consensus certificate recorded` | No finalized consensus certificate is currently available. The metric label `reason="finality_gap"` is emitted alongside the failure counter. |

Operators can alert on `rpp.runtime.consensus.rpc.failures` to detect repeated
verification errors or stalled finality and then reference the troubleshooting
guide for remediation steps.

### SDK error mapping helpers

The Rust (`rpp/chain-cli`), Go (`ffi` module), and TypeScript (`validator-ui`)
SDK layers expose typed error helpers that translate the snapshot `code` field
into structured enums. Each helper also derives retry delays from
`X-RateLimit-Reset`/`Retry-After` headers so client backoff matches the server’s
token-bucket policy. See the language-specific docs below for examples:

* Rust: `SnapshotError` and `classify_snapshot_error` in
  `rpp/chain-cli/src/snapshot_errors.rs`.
* Go: `SnapshotError` and `ClassifySnapshotResponse` in
  `ffi/snapshotclient.go`.
* TypeScript: `SnapshotError` and `snapshotRequest` in
  `validator-ui/src/lib/snapshotClient.ts`.

## Live API key rotation

RPC authentication secrets are only loaded during process startup; there is no
`SIGHUP`/on-the-fly reload path. Rotate bearer tokens or wallet API keys by
shipping updated configuration and rolling the fleet so each instance clears its
in-memory limiters and rejects the retired credential. The steps below avoid
interrupting traffic and ensure caches are refreshed as soon as a node adopts
the new secret.

### Rotation checklist

- **Prepare a new token and publish it to clients.** Distribute the credential
  via your secret store and update any reverse proxies that inject
  `Authorization`/`X-Api-Key` headers.
- **Stage configuration with the replacement secret.** Edit the active
  `network.rpc.auth_token` (or wallet `requests_per_minute` API key map) in the
  config profile or supply the new value via `--rpc-auth-token` at startup.
- **Roll nodes one at a time.** Drain each instance, start it with the updated
  token, and wait for `/health/ready` before moving to the next host. The reboot
  clears the per-tenant token-bucket cache so only the new key accrues quota.
- **Validate both paths during the overlap.** Use canary clients to confirm the
  new token returns `200` responses and the retired token immediately receives
  `401` or `429` responses once its host restarts.
- **Flush dependent caches.** If you front RPC with a proxy/CDN that caches
  `401`/`429` decisions, purge entries for RPC paths after the first host rolls
  so stale authorisation results do not linger.
- **Tear down the old secret.** After every node has restarted, revoke the prior
  token in the secret manager and remove any emergency overrides or temporary
  CORS origins added for the rotation.

### Example rotation timeline (rolling, zero-downtime)

- **T‑30 m** – Announce rotation window, push new token to clients, and lower
  proxy cache TTLs for RPC responses to ≤30 seconds.
- **T‑15 m** – Apply configuration with the new token to the first node and
  restart it with `--rpc-auth-token <new>` (or the updated config file); verify
  `/health/ready` and successful RPC requests with the new credential.
- **T‑10 m** – Restart remaining nodes sequentially. Monitor `401`/`429`
  counters to confirm the old token is rejected as each instance comes back.
- **T+5 m** – Purge any residual proxy/CDN caches for RPC paths and validate that
  quota/limit metrics reference only the new key.
- **T+30 m** – Revoke the old token in the secret store and delete temporary
  client allow lists or observability silences created for the rotation.

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

