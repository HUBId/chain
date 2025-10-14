# RPC CLI Operator Guide

This guide summarizes the operational practices for the RPC command line interface (CLI).
It covers authentication, rate limiting, handling errors surfaced by the client, and
procedures for recovering the CLI when it becomes unhealthy.

## Authentication

The RPC CLI authenticates requests to the control plane via API tokens issued by the
infrastructure team. Operators should:

- Store tokens in the CLI configuration file (`~/.config/chain/rpc_cli.toml`) with
  file permissions set to `600` to avoid accidental disclosure.
- Rotate tokens on the cadence published by security operations and update the
  configuration using `rpc-cli auth set --token <token> --endpoint <url>`.
- Verify the active token before running sensitive procedures with `rpc-cli auth status`.
  The command reports the token expiry and the identity associated with the token.
- Clear tokens for deprovisioned users using `rpc-cli auth revoke --user <handle>` and
  confirm removal in the audit log exported to `logs/rpc-cli-auth.log`.

The CLI refuses to issue requests when no valid token is configured. The CLI exits with
`AUTHENTICATION_REQUIRED` in that scenario. Review the platform security policies before
issuing emergency overrides.

## Rate limits

The RPC gateway enforces per-user and per-service budgets. To stay within limits:

- Use the `--batch-size` flag to coalesce calls that naturally group together.
- Prefer `rpc-cli schedule` over tight polling loops. The scheduler API integrates with
  the backoff policy and reduces bursts.
- Inspect rate limit headers reported by the CLI (`x-rpc-limit`, `x-rpc-remaining`, and
  `x-rpc-reset`). They are printed when verbose logging is enabled via `-v`.
- When running bulk operations, coordinate windows with other operators so that the
  aggregate quota remains below 80% of the tenant allocation.

If a command is throttled, the CLI exits with `RATE_LIMITED`. The retry-after value is
printed to stderr. Follow the recovery playbook in the [CLI recovery](#cli-recovery)
section before attempting retries.

## Error handling

The CLI classifies server and client issues. Familiarity with exit codes helps triage
incidents quickly:

| Exit code                | Meaning                         | Operator action |
| ------------------------ | ------------------------------- | ----------------|
| `SUCCESS`                | Operation completed             | Record outcome  |
| `AUTHENTICATION_REQUIRED`| Missing or expired credentials  | Renew token     |
| `RATE_LIMITED`           | Gateway throttled request       | Follow backoff  |
| `INVALID_ARGUMENT`       | CLI rejected input              | Re-run with corrected flags |
| `UPSTREAM_FAILURE`       | RPC service returned 5xx        | Escalate to the on-call service owner |
| `NETWORK_UNAVAILABLE`    | CLI could not reach gateway     | Check VPN / network policies |

The CLI writes detailed stack traces to `logs/rpc-cli-debug.log` when invoked with the
`--debug` flag. Include this artifact when opening tickets.

## CLI recovery

When the CLI encounters persistent failures:

1. Run `rpc-cli doctor`. The diagnostic tool validates authentication, connectivity,
   and local cache integrity. Resolve issues it reports before proceeding.
2. Clear the CLI cache with `rpc-cli cache purge`. This resolves most checksum and
   schema drift errors.
3. Restart the local RPC proxy (`systemctl --user restart rpc-cli-proxy`) to pick up
   configuration changes distributed through environment management.
4. If failures continue, capture the output of `rpc-cli doctor --verbose` and attach it
   to the incident tracker entry. Escalate to the infrastructure team with priority P2.

Successful recovery steps should be summarized in the shift hand-off document so that
follow-up actions are transparent to the next operator.
