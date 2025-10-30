# Admission Control Overview

The networking stack validates remote peers twice before they can affect
state: during the initial handshake and every time a gossip message arrives.
This document captures the hardening introduced to make both stages tier-aware
and observable.

## Handshake validation

`Peerstore::record_handshake` rejects peers that violate the access lists or
present inconsistent tier claims. The handler now returns a
`HandshakeOutcome` describing the decision, logs it via `telemetry.handshake`,
and persists the peer record only when the handshake is accepted.【F:rpp/p2p/src/peerstore.rs†L503-L585】

The outcome distinguishes between blocklisted peers, allowlist tier
mismatches, missing public keys or signatures, and VRF verification failures.
Successful handshakes carry an `allowlisted` flag so observability pipelines
can differentiate mandatory peers from opportunistic connections.

## Gossip tier filtering

Incoming gossip messages are filtered through `gossip::evaluate_publish`,
which wraps `AdmissionControl::can_remote_publish`. The helper records the
per-topic decision, emits structured telemetry under `telemetry.gossip`, and
propagates `AdmissionError` when a peer lacks the required tier.【F:rpp/p2p/src/gossip/mod.rs†L1-L39】【F:rpp/p2p/src/swarm.rs†L1547-L1612】

The swarm continues to reward successful publishers and penalise rejected
peers, but the tier check now happens in a single place so metrics and logs
share the same vocabulary.

## Metrics

`AdmissionMetrics` exposes counters for handshake and gossip outcomes. Both
handlers increment the counters with labels covering the decision, the peer's
tier, and rejection reasons. When the `metrics` feature is disabled the calls
become no-ops, so the instrumentation does not affect non-observability
builds.【F:rpp/p2p/src/metrics.rs†L1-L147】

## Tests

`tests/network/admission_control.rs` exercises the new failure modes: a peer
failing to meet its allowlist tier is rejected during the handshake, and a
valid tier-two peer attempting to publish consensus votes hits the expected
`TierInsufficient` error.【F:tests/network/admission_control.rs†L1-L92】
