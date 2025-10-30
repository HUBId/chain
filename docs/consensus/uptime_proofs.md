# Uptime proof flow

This document outlines how uptime proofs are produced, submitted, and ingested by
Malachite consensus.

## Scheduler lifecycle

`UptimeScheduler` runs inside the node service layer. It queries the node for
pending proofs, asks the wallet to generate a new proof when the queue is empty,
submits the result, and gossips an audit snapshot over the meta reputation
channel. Each cycle is timed and recorded via the `UptimeMetrics` histogram so
operators can monitor cadence, credited hours, and failure stages.

## Reputation integration

When consensus receives an `UptimeObservation` it routes the event through the
`MalachiteReputationManager`. The manager validates window boundaries, credits
uptime, re-computes the validator's score/tier, and records any slashing
triggers for overlapping/invalid proofs. Consensus propagates the new weights to
the active validator set so voting power reflects the latest reputation state.

## Monitoring hooks

The scheduler publishes telemetry for cycle durations, outcome counters,
pending queue snapshots, credited hours, and per-stage failure totals. Successful
submissions emit structured gossip payloads describing the validator's current
tier and score. Any rejected observations generate warning logs and retained
slashing trigger records, which consensus can surface to downstream consumers.

## Testing

`tests/consensus/uptime.rs` exercises the reputation manager and consensus
integration. The suite covers happy-path credit accrual, overlap detection, and
end-to-end propagation of new weights/slashing triggers.
