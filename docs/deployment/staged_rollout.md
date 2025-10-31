# Staged Rollout Playbook

This runbook documents the dev → testnet → canary → mainnet rollout that backs
`config/defaults/mainnet.toml`. Each stage contains readiness checks, feature
gate deltas, rollout commands, and immediate recovery actions.

## Common Preflight Checks

Run these checks before promoting any stage:

1. **Config drift.** Compare the target cluster configuration against
   `config/defaults/mainnet.toml` and ensure feature gates match the upcoming
   stage profile (`rpp-chain` `NodeConfig::load` will reject unknown keys).
2. **Binary verification.** Verify the signed release artifact matches the
   `git rev-parse` used for smoke testing and that SBOM attestation is attached.
3. **Observability.** Confirm dashboards for consensus health, proof latency,
   VRF participation, and network churn are green and alert routing is armed.
4. **Rollback assets.** Stage the previous release container and snapshot
   bundles so they can be re-deployed without rebuilding artifacts.

Document successful checks in the release issue before proceeding.

## Development Stage

### Development Readiness

* CI integration and property tests are green for the target commit.
* Cluster automation can provision fresh nodes with the development feature
  gates (Malachite consensus disabled, rewards disabled).
* Telemetry backends are reachable from the development VPC.

### Development Activation

1. Deploy nightly artifacts to the internal development cluster.
2. Run the smoke suites from `tests/pipeline` and `tests/observability` to
   validate pipeline health.
3. Capture baseline metrics for consensus latency, proof queue depth, and VRF
   participation for comparison with later stages.

### Development Recovery

If the deployment fails:

* Revert to the previous development build using automation rollbacks.
* Restore snapshots using `docs/storage_recovery.md` and replay WAL to the
  prior finalized height.
* Open an incident, collect metrics, and block promotion until resolved.

## Testnet Stage

### Testnet Readiness

* Development soak tests have passed for at least 48 hours with no paging
  alerts.
* Testnet validators have acknowledged the upgrade window.
* Feature gates toggle on `malachite_consensus` and remain off for rewards and
  witness networking per `config/defaults/mainnet.toml`.

### Testnet Activation

1. Roll the deployment to the public testnet cluster during a scheduled window.
2. Enable the malachite consensus gate and monitor validator gossip for
   stability.
3. Run the witness and proof regression suites in `tests/firewood_lifecycle`
   against the new build.

### Testnet Recovery

If regressions appear:

* Pause the rollout, announce the halt in validator channels, and redeploy the
  previous release artifacts.
* Trigger the storage recovery runbook to restore any corrupted snapshots.
* File a governance incident with impact summary and the disabled gate status.

## Canary Stage

### Canary Readiness

* Testnet has finalized 10 epochs without emergency interventions.
* Canary validators have installed the release candidate and passed dry-run
  config validation.
* Telemetry alerts for reward distribution and witness gossip are active.

### Canary Activation

1. Enable `timetoke_rewards` for the selected canary validators only.
2. Observe reward distribution and consensus voting for at least three epochs.
3. Validate witness relays remain stable before turning on the canary subset of
   the witness network clients.

### Canary Recovery

* Disable the canary feature gates (rewards, witness network) on the affected
  nodes and redeploy the previous configuration bundle.
* If the chain halts, coordinate with validators to fall back to the prior
  release snapshot and replay proofs.
* Publish a public incident report summarizing mitigations and next steps.

## Mainnet Stage

### Mainnet Readiness

* Canary metrics show no regressions after seven epochs with rewards enabled.
* All validators have signed off on the maintenance window.
* Hotfix branches are queued for any lingering low-risk issues.

### Mainnet Activation

1. Announce the activation window and freeze new governance proposals.
2. Enable `witness_network` and confirm all feature gates now match the mainnet
   profile.
3. Monitor consensus, telemetry, and proof latencies continuously for the first
   24 hours. Engage the release commander for any anomalies.

### Mainnet Recovery

* If consensus stalls, disable reward and witness gates, redeploy the canary
  configuration, and execute the storage recovery steps.
* Coordinate with validators to restore the previous snapshot and rerun proof
  verification before resuming block production.
* Convene the governance council to approve any emergency patches or gate
  reversals.

Following this playbook keeps each promotion deliberate, observable, and easily
reversible.
