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

## Phase-1 Guard Verification

Run this checklist after upgrades or incident response to confirm the compile-time, runtime, and CI
guardrails from Phase 1 are still enforced.

- [ ] **Compile-time Plonky3 guard rejects the mock backend.** From the repository root, execute
      `cargo check --features backend-plonky3,prover-mock`. The command must fail with the message
      `The Plonky3 backend cannot be combined with the mock prover feature.`, which is emitted by the
      compile-time guard and covered by the feature-matrix test suite.【F:rpp/node/src/feature_guard.rs†L1-L7】【F:rpp/node/tests/feature_matrix.rs†L6-L60】
      A successful run indicates the guard regressed and should be treated as a release blocker.
- [ ] **Runtime root-integrity guard surfaces on corrupted snapshots.** With a validator or hybrid
      node running against a known-good snapshot, overwrite one snapshot payload (for example via:
      ```sh
      python - <<'PY'
      from pathlib import Path
      snapshot = next(Path('storage/firewood/snapshots').glob('*.bin'))
      snapshot.write_bytes(b'corrupted-snapshot-payload')
      PY
      ```
      ) and trigger a state-sync chunk request. Afterwards poll the health endpoint with
      `curl -i http://localhost:26600/health/ready`; the guard should flip readiness to `503` while
      state sync returns an explicit `snapshot root mismatch` error and increments
      `rpp_node_pipeline_root_io_errors_total` until the snapshot is restored.【F:rpp/runtime/node.rs†L4007-L4043】【F:rpp/rpc/api.rs†L3027-L3070】【F:tests/state_sync/root_corruption.rs†L1-L53】【F:docs/storage/firewood.md†L58-L76】
- [ ] **CI guardrails stay green.** Validate that the GitHub `CI` workflow (which runs fmt, clippy,
      the full test matrix, and the dashboard/alert linters) succeeded by running
      `gh run watch --exit-status --workflow ci.yml` or checking the corresponding status on your
      pull request. A failed status signals missing compile/runtime protections or telemetry exports
      and must be investigated before shipping.【F:.github/workflows/ci.yml†L1-L80】【F:docs/test_validation_strategy.md†L41-L83】

| Symptom | Check | Action |
| --- | --- | --- |
| CLI exits quickly with code 2 or the message `configuration error` | Inspect the stderr output from `rpp-node` and confirm the reported exit code (2 indicates configuration failures).【F:rpp/node/src/main.rs†L18-L24】【F:rpp/node/src/lib.rs†L48-L133】 | Run the binary with `--dry-run` to surface loader errors without starting the runtime, fix the indicated configuration key (see configuration guide), and retry.【F:rpp/node/src/lib.rs†L258-L359】 |
| `/health/ready` returns `503 Service Unavailable` | Query `/health` and `/health/ready` on the RPC address to see which role is failing readiness; the handler requires node, wallet, and (for validator mode) orchestrator to be enabled.【F:rpp/rpc/api.rs†L1102-L1145】 | Check startup logs for the absence of `node runtime started`, `wallet runtime initialised`, or `pipeline orchestrator started`; resolve configuration errors (ports, telemetry, secrets) until all markers appear and readiness flips to `200`.【F:rpp/node/src/lib.rs†L442-L553】【F:rpp/node/src/lib.rs†L722-L775】 |
| Runtime starts but RPC is unreachable | Confirm `rpc endpoint configured` was logged and verify the configured `network.rpc.listen` socket is free of conflicts (hybrid/validator enforce identical node/wallet listeners).【F:rpp/node/src/lib.rs†L448-L530】【F:rpp/node/src/lib.rs†L722-L775】 | Adjust the listener ports in the config templates or CLI flags to remove clashes and restart. Use `--write-config` after a successful dry run to persist the updated settings.【F:rpp/node/src/lib.rs†L229-L357】 |

Once the runtime is healthy, continue with the [observability runbook](observability.md) to verify
telemetry and dashboards. Use the [pipeline telemetry dashboards](../observability/pipeline.md) to
confirm wallet, proof, consensus, and storage phases recover after remediation.

