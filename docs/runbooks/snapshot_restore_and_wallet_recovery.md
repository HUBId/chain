# Snapshot restore and wallet recovery guide

This guide walks responders through restoring node state from exported snapshots, re-running pruning when checkpoints are missing, and recovering wallet keys and balances. It also captures zero-knowledge backend verification checks and uptime/timetoke guardrails to confirm the recovered node is trustworthy before rejoining traffic.

## 1. Prepare the host and artifacts

1. **Stop daemons and mount storage read-only.** Halt services (`systemctl stop rpp-node rpp-wallet` or equivalent) and remount the data volume read-only to prevent writes during verification.
2. **Stage artifacts.** Download the most recent storage snapshot bundle and any wallet backup archives to a staging directory. Keep the checksum manifest alongside the artifacts for validation.
3. **Pair backups with snapshots.** Place the encrypted wallet archive (or the full `backups/` directory) in the same staging path as the node snapshot so operators can restore both together without re-downloading secrets. Record the checksum for the backup separately and note the embedded checkpoint height/epoch so you can confirm it matches the snapshot tip before running the wallet restore command.【F:docs/wallet_operator_runbook.md†L99-L130】
4. **Validate inputs.** Check hashes before applying them:
   ```bash
   sha256sum -c snapshot.SHA256SUMS
   sha256sum -c wallet-backups.SHA256SUMS
   ```
   Reject any bundle that fails verification to avoid replaying corrupted state.

## 2. Restore node state from snapshot

1. **Install the snapshot into `data_dir/db`.** Replace the RocksDB column families with the extracted snapshot files, keeping ownership and permissions intact:
   ```bash
   tar -xzf firewood-snapshot.tar.gz -C /var/lib/rpp-node/data/db
   chown -R rpp:rpp /var/lib/rpp-node/data/db
   ```
2. **Rehydrate the WAL if present.** If a `firewood.wal` file exists in the snapshot, leave it in place so the runtime replays the log. If WAL corruption was the reason for the restore, delete the WAL before restarting so the node rebuilds it from the snapshot state.
3. **Restart and verify storage health.** Start the node and confirm the storage guardrails recover:
   ```bash
   rpp-chain validator health --rpc-url http://<host>:<port>
   curl -s http://<host>:<port>/status/storage | jq '.snapshot.head, .pruning.head'
   ```
   The validator health command returns exit code `0` only when pruning, wallet, consensus, and backend subsystems report ready markers that match the lifecycle tests.【F:docs/operator-guide.md†L12-L48】 The storage status should show `snapshot.head` advancing toward `pruning.head` without large gaps.

## 3. Re-run pruning and validate checkpoints

1. **Pause automated pruning while rebuilding.** Prevent further eviction while checkpoints are audited:
   ```bash
   rppctl pruning pause
   ```
2. **Rebuild pruning envelopes.** Enqueue a full rebuild so the node reconstructs pruning checkpoints from the restored snapshot:
   ```bash
   curl -sS -X POST \
     -H "Authorization: Bearer $RPP_RPC_TOKEN" \
     http://<host>:<port>/snapshots/rebuild
   ```
3. **Track progress and receipts.** Poll the pruning status until `missing_heights` empties and receipts report `accepted=true`:
   ```bash
   curl -s http://<host>:<port>/snapshots/jobs | jq '.jobs[0]'
   ```
   Receipts include validation details surfaced by the pruning service so operators can triage without logs.【F:docs/runbooks/pruning.md†L35-L83】
4. **Resume automation.** Once checkpoints verify, resume pruning and watch the cadence recover:
   ```bash
   rppctl pruning resume
   curl -s http://<host>:<port>/status/storage | jq '.pruning.head'
   ```
5. **Cross-check proof readiness.** If recursive proofs depend on pruning proofs, run the release-feature verification to ensure no mock/unsupported backends are linked before reopening traffic:
   ```bash
   ./scripts/verify_release_features.sh --target x86_64-unknown-linux-gnu --profile release
   ```
   Pair the result with `/status/node` backend health snapshots to confirm the active prover matches policy.【F:RELEASE.md†L24-L43】【F:scripts/verify_release_features.sh†L1-L35】

## 4. Recover wallet keys and state

1. **Restore encrypted backups.** Import the most recent backup archive and validate the passphrase profile and checkpoint alignment:
   ```bash
   cargo run -p rpp-wallet --features "runtime backup" -- \
     backup restore --path /var/lib/rpp-wallet/backups/manual.rppb
   ```
   The restore flow enforces the Argon2id profile and checksum recorded with the archive; `backup validate` returns an error if the captured checkpoint height/epoch diverges from the staged node snapshot.【F:docs/wallet_phase4_advanced.md†L9-L36】
2. **Inspect keystore readiness.** After restore, confirm the keystore loads and wallet health probes report ready:
   ```bash
   rpp-wallet migrate --wallet-config /etc/rpp/wallet.toml
   curl -s http://<host>:<port>/health/ready | jq '.wallet_signer_ready, .wallet_key_cache_ready'
   ```
   `wallet_signer_ready=true` and `wallet_key_cache_ready=true` indicate the signer and key cache are hydrated before traffic resumes.【F:docs/wallet_operator_runbook.md†L225-L243】
3. **Rebuild wallet state if snapshots lag.** When restoring from old seeds or backups, trigger a focused rescan to re-index missing history:
   ```bash
   rpp-wallet rescan --from-height <last-known-height> --wallet-config /etc/rpp/wallet.toml
   ```
   Match `wallet.engine.birthday_height` to the restored snapshot so deposits are not skipped.【F:docs/wallet_operator_runbook.md†L174-L183】
4. **Validate balances and policy enforcement.** List accounts and run a small send to prove policies and prover settings match the deployment:
   ```bash
   rpp-wallet accounts list --wallet-config /etc/rpp/wallet.toml
   rpp-wallet send --to <address> --amount <amt> --wallet-config /etc/rpp/wallet.toml
   ```
   Use the wallet monitoring panels to confirm prover/fee metrics update during the send.【F:docs/wallet_monitoring.md†L1-L70】

## 5. Uptime and timetoke considerations post-restore

1. **Check uptime proof continuity.** Query the uptime/timetoke counters to ensure rewards and participation accounting remained monotonic through the restore:
   ```bash
   curl -s http://<host>:<port>/status/node | jq '.uptime_proofs, .timetoke_root'
   ```
   Drops in counters or a changed `timetoke_root` indicate missed uptime proofs; run the timetoke SLO report if drift is detected.
2. **Re-run timetoke SLO summary (optional).** Generate a seven-day replay summary from Prometheus or stored metrics to validate replay latency and success rates after the restore:
   ```bash
   cargo xtask report-timetoke-slo --prometheus-url $PROM_URL --bearer-token $PROM_TOKEN --output timetoke-slo.txt
   ```
   The report highlights replay success/failure counts and latency quantiles so responders can decide whether to keep the node in rotation.【F:xtask/src/main.rs†L5588-L5592】【F:xtask/src/main.rs†L3797-L3847】
3. **Monitor uptime dashboards.** Load the uptime/finality correlation dashboard to verify alerts track the recovered node and that uptime/finality pairs remain within SLO thresholds before closing the incident.【F:docs/dashboards/uptime_finality_correlation.json†L1-L200】【F:RELEASE.md†L41-L43】

## 6. Incident documentation and handoff

- Record snapshot sources, checksum outputs, pruning receipts, wallet restore commands, and backend verification results in the shared incident log. The incident response and operator guides link back to this page—keep those references updated when steps change.
- Capture the final `/status/node`, `/status/storage`, and `/health/ready` payloads to demonstrate recovered readiness across storage, pruning, backend, wallet, and timetoke subsystems before returning the node to production.
