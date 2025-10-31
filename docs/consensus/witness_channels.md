# Witness Gossip Channels & Reward Bookkeeping

This document captures the operator-facing behaviour of the dedicated witness
pipelines that were introduced alongside the Malachite blueprint roll-out. It
covers the queueing semantics for witness proofs and metadata, the network QoS
settings, and the reward accounting hooks that bind witness payouts to the
Treasury and fee pools.

## 1. Dedicated witness gossip buffers

Witness gossip no longer flows through the generic proof mempool. Instead the
libp2p behaviour exposes a `WitnessGossipPipelines` helper with two isolated
channels:

- **Proof channel** – stores witness proof bundles, enforces a strict rate limit
  and retains the most recent `witness_proof_buffer` payloads.
- **Meta channel** – carries heartbeat and QoS telemetry for witnesses. The
  buffer length and rate limit are tuned separately via
  `witness_meta_buffer`/`witness_meta_rate_limit` so noisy metadata cannot evict
  proofs.

Each channel is backed by a token-bucket rate limiter that replenishes every
`witness_rate_interval_ms`. When the allowance is exhausted the behaviour emits
`WitnessPipelineError::RateLimited`, allowing the admission layer to penalise
noisy peers before the payload reaches consensus processing.

The defaults (256 proof entries, 128 metadata entries, 128/64 messages per
interval) match the values published in `config/malachite.toml` and can be
overridden per deployment.

## 2. Topic priorities and QoS classes

`GossipTopic::metadata()` now annotates every canonical gossip topic with a
priority and a coarse QoS class:

| Topic                     | Priority  | QoS        | Notes                                             |
|---------------------------|-----------|------------|---------------------------------------------------|
| `/rpp/gossip/witness/proofs/1.0.0` | Critical | Throughput | Proof bundles must never starve behind bulk traffic |
| `/rpp/gossip/witness/meta/1.0.0`   | High     | Telemetry  | Health beacons and rate reports                   |
| `/rpp/gossip/meta/1.0.0`           | Low      | Telemetry  | Background network inventory                      |

The metadata feeds directly into the gossipsub scoring policy and is consumed by
operators to prioritise transport classes on the wire.

## 3. Treasury integration for witness payouts

Consensus reward distribution tracks the configured Treasury accounts and
witness pool weights. When a block finalises the pipeline now:

1. Computes the validator distribution (base reward + leader bonus) and records
   the total debit against `treasury-validator`.
2. Applies witness payouts recorded by the evidence pipeline and splits the
   aggregate across `treasury-witness` and `treasury-fees` according to the
   `rewards.witness_pool_weights` ratios.
3. Persists the per-witness credits so the ledger can materialise them during
   block execution.

The resulting `RewardDistribution` snapshot contains the raw reward maps and the
ledger bookkeeping fields (`validator_treasury_debit`,
`witness_treasury_debit`, `witness_fee_debit`) so downstream components and
operators can reconcile budget flows.

## 4. Operational checklist

* Confirm that `config/malachite.toml` advertises the intended buffer and
  rate-limit values for witness channels before rolling out to production.
* Monitor the witness QoS metrics surfaced by `rpp/p2p/tests/witness_qos.rs` to
  ensure rate-limiting behaves as expected in CI.
* Validate reward ledgers via `tests/consensus/witness_distribution.rs` whenever
  Treasury accounts or witness weight ratios change.
