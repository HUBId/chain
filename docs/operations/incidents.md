# Incident response runbook

> **Scope:** Central runbook for consensus forks, verifier outages/failover, and pruning recovery.
> Keep this page linked from operator, consensus, and backend docs so updates ship with feature changes. Pair pruning or snapshot
> rebuilds with the [snapshot restore and wallet recovery guide](../runbooks/snapshot_restore_and_wallet_recovery.md) so state
> verification and wallet restores follow the same checklist across rotations.

## Expectations and escalation

- **Paging/acknowledgement:** Acknowledge PagerDuty/alertmanager pages within **5 minutes** and post the owning responder.
- **Stabilisation target:** Reach a steady state (traffic drained or service restored) within **30 minutes**. Escalate to the
  **release engineering** and **SRE** rotations if progress stalls at **20 minutes**.
- **Incident log:** Record timelines, commands executed, metric snapshots, and configuration overrides in the shared operations
  log. Attach postmortems within **48 hours** of closure.

## Fork-handling playbook

1. **Confirm fork depth and actors**
   - `curl -s http://<node>:<port>/status/consensus | jq '.accepted_height, .finalized_height, .proposer'`
   - Compare `accepted_height` and `finalized_height` across at least three validators to validate divergence depth.
   - Metrics: `consensus_fork_choice_reorgs_total`, `finality_lag_slots`, and `finalized_height_gap` should be checked for
     spikes (Grafana or `promtool query` if dashboards are unavailable).
2. **Isolate and fence offenders**
   - Disconnect peers that advertise stale heads: `rppctl peer block --peer <peer_id> --reason forked_head`.
   - Stop gossip to quarantined nodes: update admission policies or apply a temporary denylist via `fwdctl peers block`.
3. **Rebuild agreement**
   - If the canonical head is unclear, force a safety halt on affected validators: `systemctl stop rpp-node` and snapshot logs
     with `journalctl -u rpp-node -S -10m`.
   - Promote the healthiest branch by restarting a quorum with the highest finalized height first, then reintroducing others.
   - Validate catch-up: `curl -s http://<node>/status/consensus | jq '.finalized_height'` should increase monotonically across
     the restarted quorum; alert if heights regress.
4. **Post-fork verification**
   - Run the reorg drill locally if time permits: `cargo test -p tests --test reorg_rpp_stark -- --ignored` to reproduce
     acceptance/rejection paths.
   - Close the incident only after `consensus_fork_choice_reorgs_total` stops increasing for **two consecutive evaluation
     windows** and all validators report matching `finalized_height`.

## Verifier outage and failover

1. **Detect and confirm impact**
   - Metrics: `rpp_stark_stage_checks_total{result="fail"}` and
     `histogram_quantile(0.95, rate(rpp_stark_verify_duration_seconds_bucket[5m]))`.
   - Health snapshot: `curl -s http://<node>/status/node | jq '.backend_health["rpp-stark"].verifier'` to check `accepted`
     vs `rejected` and cache eviction counters.
2. **Fail over to healthy backend**
   - Switch backend configuration to the alternate verifier/prover set (for example, Plonky3 fallback): update
     `backend = "plonky3"` in `node.toml` (or feature-flag equivalent) and restart: `systemctl restart rpp-node`.
   - Verify the swap: `/status/node` should show the new backend under `backend_health`, and
     `rpp.runtime.verifier.accepted_total{backend="plonky3"}` should begin increasing within **5 minutes** of restart.
3. **Stabilise queues and clients**
   - Flush stuck proofs: `rppctl proofs clear --backend rpp-stark --reason outage` (clears gossip proof cache while retaining
     chain data).
   - Monitor mempool drain: `curl -s http://<node>/status/mempool | jq '.pending_transactions'` should trend to zero after the
     backend swap; investigate if it stalls for more than **10 minutes**.
4. **Escalate and roll forward**
   - If failover fails or latency remains above SLO for **15 minutes**, page the **proofs on-call** and **release engineering**.
   - Capture evidence: save `rpp-node` logs with `rpp.proofs` target, and export the last 15 minutes of metrics with
     `promtool query range` for the affected counters.

## Pruning recovery

1. **Detect pruning gaps**
   - Alerts: `pruning_checkpoint_lag_slots` or `storage_firewood_pruning_errors_total` firing indicates pruning stalled.
   - Verify state: `/status/storage` should show `pruning.head` and `snapshot.head`; gaps larger than **64 slots** require
     intervention.
2. **Rebuild checkpoints**
   - Pause pruning to avoid further divergence: `rppctl pruning pause`.
   - Rehydrate snapshots: `curl -X POST http://<node>/snapshots/rebuild` or restore from baseline exports into
     `storage.firewood.snapshots`.
   - Resume once rebuild completes: `rppctl pruning resume`.
3. **Validate ledger health**
   - Compare `pruning.head` against `finalized_height` until the delta is < **8 blocks** and stable for **15 minutes**.
   - Metrics to confirm recovery: `storage_firewood_pruned_blocks_total` increasing without corresponding error increments,
     and `pruning_checkpoint_lag_slots` returning to zero.
4. **Close-out**
   - Run `cargo test --test pruning_recovery -- --ignored` if available in CI to mirror the recovery path.
   - Document snapshot sources, rebuild duration, and any data restored from backups before resolving the incident.

## Contacts and ownership

- **Primary:** On-call SRE (PagerDuty schedule: `rpp-sre`).
- **Secondary:** Release engineering (`rpp-releng`), Proof/Verifier owners (`rpp-proofs`), and Storage maintainers
  (`rpp-storage`).
- **Security escalation:** Security liaison on-call (`rpp-security`) for suspected malicious forks or proof tampering.
