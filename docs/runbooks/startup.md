# Startup runbook

Follow this guide when a runtime fails to start or health probes remain unhealthy. Combine it with the
[configuration](../configuration.md) reference and [observability](observability.md) runbook for full
context.

> **Note:** Authenticated deployments must send an `Authorization: Bearer …` header when polling the
> health endpoints. For example:
>
> ```sh
> curl -H "Authorization: Bearer ${RPP_HEALTH_TOKEN}" https://rpc.example.org/health/ready
> ```
>
> See the [API security hardening guide](../API_SECURITY.md) for details on retrieving or rotating the
> health probe token.

| Symptom | Check | Action |
| --- | --- | --- |
| CLI exits quickly with code 2 or the message `configuration error` | Inspect the stderr output from `rpp-node` and confirm the reported exit code (2 indicates configuration failures).【F:rpp/node/src/main.rs†L18-L24】【F:rpp/node/src/lib.rs†L48-L133】 | Run the binary with `--dry-run` to surface loader errors without starting the runtime, fix the indicated configuration key (see configuration guide), and retry.【F:rpp/node/src/lib.rs†L258-L359】 |
| `/health/ready` returns `503 Service Unavailable` | Query `/health` and `/health/ready` on the RPC address to see which role is failing readiness; the handler requires node, wallet, and (for validator mode) orchestrator to be enabled.【F:rpp/rpc/api.rs†L1102-L1145】 | Check startup logs for the absence of `node runtime started`, `wallet runtime initialised`, or `pipeline orchestrator started`; resolve configuration errors (ports, telemetry, secrets) until all markers appear and readiness flips to `200`.【F:rpp/node/src/lib.rs†L442-L553】【F:rpp/node/src/lib.rs†L722-L775】 |
| Runtime starts but RPC is unreachable | Confirm `rpc endpoint configured` was logged and verify the configured `network.rpc.listen` socket is free of conflicts (hybrid/validator enforce identical node/wallet listeners).【F:rpp/node/src/lib.rs†L448-L530】【F:rpp/node/src/lib.rs†L722-L775】 | Adjust the listener ports in the config templates or CLI flags to remove clashes and restart. Use `--write-config` after a successful dry run to persist the updated settings.【F:rpp/node/src/lib.rs†L229-L357】 |

Once the runtime is healthy, continue with the [observability runbook](observability.md) to verify
telemetry and dashboards. Use the [pipeline telemetry dashboards](../observability/pipeline.md) to
confirm wallet, proof, consensus, and storage phases recover after remediation.

