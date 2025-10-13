# Threat Model Overview

This document captures the primary attack surfaces for the chain node and the mitigations that are currently implemented or planned. It is intended to provide engineers with actionable guidance when extending the system and to tie mitigations back to automated coverage where possible.

## RPC Interface

**Threats**
- Flooding the HTTP API with unauthenticated traffic to exhaust worker threads or overwhelm business logic.
- Bypassing per-route throttling by rotating between endpoints.
- Brute forcing bearer tokens for privileged endpoints.

**Mitigations**
- Enforce a global rate limit across all RPC routes. This is covered by the integration test `rate_limit_applies_to_mixed_routes` in `tests/rpc_endpoints.rs`, which demonstrates that the limit is enforced even when alternating between endpoints.【F:tests/rpc_endpoints.rs†L142-L187】
- Require explicit bearer tokens for privileged calls; negative authentication paths are covered in the existing `rpc_endpoints` integration suite.
- Keep rate-limit configuration surfaced in `NodeConfig` so deployments can tune limits per environment.

**Action Items**
- Extend coverage for streaming or long-lived RPC calls once implemented to ensure they cooperate with the limiter.

## P2P Handshake & Gossip

**Threats**
- Oversized handshake payloads (e.g., extremely large VRF proofs) intended to exhaust memory during connection setup.
- Replay of stale VRF proofs or impersonation attempts during the handshake phase.

**Mitigations**
- The handshake codec enforces an 8 KiB bound. The integration test `handshake_messages_over_limit_are_rejected` in `tests/p2p_handshake_limits.rs` asserts that oversized payloads are rejected before allocating unbounded buffers.【F:tests/p2p_handshake_limits.rs†L10-L57】
- Handshake signatures and VRF verification remain enforced by `Peerstore::record_handshake`; additional negative-path coverage can be added as new identity schemes are introduced.

**Action Items**
- Add fuzzing around the handshake codec to exercise boundary conditions and malformed JSON payloads.

## Consensus Pipeline

**Threats**
- Vote replay attacks where a malicious validator floods the leader with duplicate prevotes/precommits to inflate perceived quorum and stall progress.
- Submission of votes that reference stale or mismatched block hashes.

**Mitigations**
- `ConsensusRound` de-duplicates votes by voter address. The integration test `consensus_ignores_duplicate_votes` in `tests/consensus_vote_replay.rs` confirms that repeated submissions from the same validator do not increase accumulated voting power.【F:tests/consensus_vote_replay.rs†L12-L97】
- Existing consensus evidence tests ensure conflicting votes produce slashing evidence and are not accepted for finalization.

**Action Items**
- Track view timeout metrics in CI once the async consensus loop lands to detect liveness regressions automatically.

## Storage & State Management

**Threats**
- Persistence of stale or malicious account records after a snapshot is applied, enabling replay or balance forgery.
- Downgrade attacks via schema tampering that attempt to load an older schema version without migration.

**Mitigations**
- `Storage::apply_account_snapshot` rewrites the authoritative account set. The integration test `account_snapshots_prune_missing_identities` in `tests/storage_snapshot_sanitization.rs` shows that entries missing from a snapshot are deleted, preventing stale state retention.【F:tests/storage_snapshot_sanitization.rs†L10-L79】
- Opening storage enforces the schema version; deviations surface as migration errors before data is read.

**Action Items**
- Extend snapshot validation to include cryptographic commitments once Firewood proofs are integrated.

## Continuous Auditing

- Dependency advisories are now checked in CI via `cargo audit`, ensuring new vulnerabilities surface during code review.【F:.github/workflows/stable-ci.yml†L69-L110】

## Operational Guidance

- **Incident response**: if abnormal network load is detected, operators can tighten `rpc_requests_per_minute` and rely on the documented tests when assessing regressions.
- **Regression detection**: when modifying handshake or consensus code paths, run the integration tests referenced above to ensure mitigations remain intact.

