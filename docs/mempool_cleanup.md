# Mempool Cleanup Runbook

This runbook captures the remediation flow validated by the spam and DoS
integration suites. The scenarios in
`tests/mempool/spam_recovery.rs::high_volume_spam_triggers_rate_limits_and_recovers`
and `tests/mempool/status_probe.rs::mempool_status_probe_flags_queue_saturation_alerts`
exercise the limiter, gossip drains, queue telemetry, and post-incident
monitoring that operators rely on during production incidents.【F:tests/mempool/spam_recovery.rs†L13-L145】【F:tests/mempool/status_probe.rs†L145-L199】

## Prerequisites

* RPC access (and bearer token if the node enforces RPC auth).
* `jq` installed locally for parsing JSON responses.
* Access to the validator CLI (`rpp-node`/`chain-cli`) on the host for
  telemetry snapshots.【F:docs/validator_tooling.md†L1-L53】

Export the RPC endpoint and auth token before running the commands:

```sh
export RPC_URL="http://127.0.0.1:7070"
export RPP_RPC_TOKEN="$(cat /var/run/rpp/rpc.token)"   # adjust for your deployment
```

## 1. Confirm the limiter tripped

1. Grep the validator logs or client errors for `mempool full`. The spam recovery
   test asserts that every overflow submission fails with this error string, so
   its presence confirms the limiter is engaged.【F:tests/mempool/spam_recovery.rs†L53-L70】
2. Capture the live queue occupancy and queue weights. `/status/mempool` mirrors
   the snapshot asserted by the tests—when the limiter fires the transaction
   queue equals the configured limit, the maximum fee remains observable, and the
   priority/fee weights surface in the payload.【F:tests/mempool/spam_recovery.rs†L74-L101】

   ```sh
   curl -sS -H "Authorization: Bearer $RPP_RPC_TOKEN" \
     "$RPC_URL/status/mempool" \
     | jq '{transactions: (.transactions | length), identities: (.identities | length), votes: (.votes | length), uptime: (.uptime_proofs | length), queue_weights}'
   ```
3. Alert responders using the same thresholds exercised by the probe scenario
   (≥80 % warning, ≥100 % critical). The probe builds a saturated snapshot and
   verifies both severities, so on-call staff can escalate as soon as the same
   ratios appear in production.【F:tests/mempool/status_probe.rs†L172-L199】

## 2. Drain the gossip backlog

1. Attach a temporary consumer to the witness proofs stream so queued gossip is
   flushed before resuming production submissions. The recovery test drains the
   broadcast channel after the limiter fires to avoid replaying stale payloads
   later.【F:tests/mempool/spam_recovery.rs†L39-L44】【F:tests/mempool/spam_recovery.rs†L72-L72】

   ```sh
   # Stream witness proof gossip as NDJSON until the backlog empties
   rpp-node validator telemetry --rpc-url "$RPC_URL" --pretty --auth-token "$RPP_RPC_TOKEN" \
     | jq '{witness_events: .consensus.witness_events}'
   ```

   Leave the stream running until the witness event counter stops climbing while
   the mempool remains saturated. This mirrors the test expectation that gossip
   stays drained throughout the probe.【F:tests/mempool/status_probe.rs†L157-L171】
2. When the counter stabilises, stop the consumer; the gossip backlog is clear
   and won’t re-play stale payloads during analysis.【F:tests/mempool/spam_recovery.rs†L72-L72】

## 3. Expand headroom and re-submit priority transactions

1. Temporarily raise the mempool limit to accept new work while the backlog is
   cleared. The integration test calls `update_mempool_limit` before injecting
   recovery transactions; the same `/control/mempool` endpoint is exposed over
   HTTP and returns the updated status snapshot.【F:tests/mempool/spam_recovery.rs†L103-L121】【F:rpp/rpc/api.rs†L1441-L1472】

  ```sh
  curl -sS -X POST "$RPC_URL/control/mempool" \
    -H "Authorization: Bearer $RPP_RPC_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"limit": 16384}' \
    | jq '{transactions: (.transactions | length), queue_weights}'
  ```
2. If spam pressure requires fee rebalancing, adjust the queue weights in the
   same request. The runtime enforces the priority/fee split exercised in the
   recovery test, so operators can restore preferred ratios without a restart.【F:tests/mempool/spam_recovery.rs†L98-L101】【F:docs/development/tooling.md†L134-L138】

   ```sh
   curl -sS -X POST "$RPC_URL/control/mempool" \
     -H "Authorization: Bearer $RPP_RPC_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"priority_weight": 0.6, "fee_weight": 0.4}' \
     | jq '.queue_weights'
   ```
3. Re-submit the blocked high-priority transactions through your standard
   tooling. The test suite confirms that, once the limit increases, new gossip
   events arrive with the expected hash and fee, proving that legitimate traffic
   can resume immediately.【F:tests/mempool/spam_recovery.rs†L107-L122】

## 4. Monitor recovery and restore steady-state limits

1. Track the aggregate backlog via `/status/node`. Pending transactions should
   rise to the temporary limit and then fall as blocks are produced, matching the
   recovered metrics asserted by the integration test.【F:tests/mempool/spam_recovery.rs†L124-L131】

   ```sh
   watch -n 2 "curl -sS -H 'Authorization: Bearer $RPP_RPC_TOKEN' $RPC_URL/status/node | jq '{pending_transactions}'"
   ```
2. Continue polling `/status/mempool` to confirm that high-fee entries are
   present and the queue now honours the updated weights.【F:tests/mempool/spam_recovery.rs†L133-L145】

   ```sh
   watch -n 2 "curl -sS -H 'Authorization: Bearer $RPP_RPC_TOKEN' $RPC_URL/status/mempool | jq '{max_fee: (.transactions | map(.fee) | max), queue_weights}'"
   ```
3. Use the validator telemetry CLI to snapshot gossip and queue totals in a
   single call. The telemetry payload aggregates the same fields enforced by the
   tests, making it a convenient final verification before declaring recovery.【F:tests/mempool/spam_recovery.rs†L39-L44】【F:tests/mempool/spam_recovery.rs†L124-L145】【F:docs/validator_tooling.md†L29-L53】

   ```sh
   rpp-node validator telemetry --rpc-url "$RPC_URL" --pretty --auth-token "$RPP_RPC_TOKEN" \
     | jq '{witness_events: .consensus.witness_events, mempool: .mempool}'
   ```
4. When the backlog stabilises and telemetry matches pre-incident levels, lower
   the limit back to its steady-state value using `/control/mempool`, mirroring
   the final step in the recovery test.【F:tests/mempool/spam_recovery.rs†L133-L145】【F:rpp/rpc/api.rs†L1441-L1472】

  ```sh
  curl -sS -X POST "$RPC_URL/control/mempool" \
    -H "Authorization: Bearer $RPP_RPC_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"limit": 8192}' \
    | jq '{transactions: (.transactions | length), queue_weights}'
  ```

Following this flow mirrors the integration coverage: detect `mempool full`
errors, drain queued gossip so investigations aren’t polluted by stale payloads,
expand headroom long enough to accept legitimate traffic, and continuously
monitor `/status/node`, `/status/mempool`, and validator telemetry until the
queues stabilise.
