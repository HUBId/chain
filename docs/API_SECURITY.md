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

## Rate limiting and abuse protections

The RPC server can enforce a global requests-per-minute limit via the
`network.limits.per_ip_token_bucket` configuration block. When enabled, an Axum
`RateLimitLayer` wraps all routes and throttles clients exceeding the budget.【F:config/validator.toml†L17-L48】【F:rpp/rpc/api.rs†L400-L520】【F:rpp/rpc/api.rs†L960-L1047】

- Combine rate limiting with reverse proxies (e.g., Envoy, NGINX) for per-IP
  accounting. The in-process limiter is intentionally simple and guards against
  runaway automation rather than targeted floods.
- Telemetry and health endpoints share the same limiter; if collectors require
  higher throughput, raise the limit or front the RPC with a cache for read-only
  paths.

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
