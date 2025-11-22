# API security hardening

Firewood exposes a rich RPC surface that powers validator operations, wallet
interactions, rollout governance, and telemetry. This guide documents the
available controls and recommended deployment patterns for production-facing
endpoints.

## Authentication and authorisation

The RPC router wraps all handlers in an optional bearer-token middleware. When an
`rpc_auth_token` is configured—either in the active `config/*.toml` file or via
`--rpc-auth-token`—requests must carry an `Authorization: Bearer <token>` header
or they are rejected with `401` responses.【F:config/validator.toml†L1-L34】【F:rpp/node/src/lib.rs†L1052-L1078】【F:rpp/rpc/api.rs†L400-L520】

- Tokens set through CLI flags override (or clear) the configuration value,
  enabling temporary rotations without editing files.【F:rpp/node/src/lib.rs†L143-L216】【F:rpp/node/src/lib.rs†L1052-L1078】
- The middleware allows CORS preflight traffic to pass without credentials so
  browser clients can negotiate headers before attaching the token.【F:rpp/rpc/api.rs†L780-L829】
- Per-endpoint authorisation is currently coarse-grained; protect critical
  methods (e.g., `/consensus/*`, `/validator/*`) by keeping the token secret and
  restricting network-level access (mTLS or IP allow lists).
- For live rotations, follow the [RPC API key rotation](./interfaces/rpc/README.md#live-api-key-rotation)
  checklist so updated secrets roll out without service interruption or stale
  limiter caches.

## Rate limiting and abuse protections

The RPC server exposes two complementary limiters:

- **Per-API-key budgets**. When `wallet.rpc.requests_per_minute` (or the
  equivalent CLI override) is set, each API key is assigned an isolated token
  bucket keyed by `Authorization` or `X-Api-Key` headers. Exceeding the quota
  returns `429` responses with `X-RateLimit-*` headers scoped to the offending
  tenant; other tenants can continue issuing requests with their own budgets.【F:config/wallet.toml†L23-L33】【F:rpp/node/src/lib.rs†L360-L418】【F:rpp/rpc/api.rs†L1511-L1615】【F:rpp/rpc/api.rs†L1938-L1954】
- **Per-IP token bucket**. `network.limits.per_ip_token_bucket` remains the
  first line of defence against noisy neighbours and unauthenticated floods.
  Tune burst and replenish values alongside upstream reverse proxies to achieve
  the desired concurrency envelope.【F:config/validator.toml†L17-L48】【F:rpp/runtime/config.rs†L1578-L1725】【F:rpp/rpc/api.rs†L1487-L1579】

Operational guidance:

- Provision distinct API keys for each tenant or automation domain so budgets
  cannot be stolen across customers. The limiter echoes remaining budget and
  next-reset seconds on `429` responses to aid client-side backoff strategies.
- Telemetry and health endpoints share the same tenant-scoped limiter; if
  collectors require larger headroom, increase the per-minute budget or front
  those routes with a cache to amortise reads.
- The limiter exports `rpp.runtime.rpc.rate_limit.total` with `method`/`status`
  labels to split normal and throttled traffic by RPC handler for dashboards and
  alerts.【F:rpp/runtime/telemetry/metrics.rs†L124-L150】

## Cross-origin access

Set `network.rpc.allowed_origin` in the active node configuration to enable CORS for
browser dashboards. Operators can temporarily override (or clear) the setting with
`--rpc-allowed-origin`, which trims the provided value and persists the override only
for the current process; restarting without the flag restores the value from the TOML
profile.【F:config/validator.toml†L1-L48】【F:rpp/node/src/lib.rs†L229-L327】【F:rpp/node/src/lib.rs†L1647-L1668】
The middleware whitelists the resolved origin, mirrors it on responses, and handles
preflight OPTIONS requests.【F:rpp/rpc/api.rs†L400-L520】【F:rpp/rpc/api.rs†L780-L829】

For example, to grant a dashboard temporary access during a maintenance window:

```sh
cargo run -p rpp-chain -- validator --rpc-allowed-origin https://dash.example --dry-run
```

Passing an empty string (`--rpc-allowed-origin ""`) clears the allow-list until the
next restart.

Avoid using `*`; Axum requires a concrete origin, which matches the goal of
restricting access to trusted dashboards.

## Telemetry endpoint security

Telemetry exporters share the authentication and endpoint override plumbing used
by the RPC server. Operators should:

- Enable telemetry intentionally via `[rollout.telemetry]` in the active config
  profile (node, hybrid, or validator). Validator mode ships with telemetry on
  and samples every 15 seconds.【F:config/validator.toml†L49-L70】【F:rpp/runtime/config.rs†L894-L912】
- Provide `--telemetry-endpoint` and, if needed, `--telemetry-auth-token` CLI
  overrides when bootstrapping into new environments. Empty CLI values clear
  stored secrets to disable exporters temporarily.【F:rpp/node/src/lib.rs†L143-L216】【F:rpp/node/src/lib.rs†L1070-L1078】
- Monitor the `telemetry` log target for warnings about dropped batches or
  disabled exporters; the runtime reports degraded states so operators can react
  before metrics gaps impact alerting.【F:rpp/runtime/telemetry/exporter.rs†L68-L133】【F:rpp/runtime/telemetry/metrics.rs†L31-L70】

## Governance integration

Security-sensitive endpoints (validator telemetry, VRF rotation, rollout status)
feed into release decision-making and fleet monitoring. Review
[`GOVERNANCE.md`](GOVERNANCE.md) for expectations around change approval, release
sign-off, and incident reporting. Threat modelling context lives in
[`THREAT_MODEL.md`](THREAT_MODEL.md), while key lifecycle steps are documented in
[`KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md).
