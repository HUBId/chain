# Poseidon VRF Specification

## Purpose & Scope
This document defines the end-to-end behaviour of the Poseidon-based Verifiable
Random Function (VRF) pipeline that drives validator selection. It consolidates
the developer notes in `docs/poseidon_vrf.md` and the roadmap deliverables for
Epoch management, monitoring, and Timetoke synchronisation into a single,
reviewable specification. Implementation teams MUST treat the requirements here
as the authoritative contract for the VRF engine, supporting services, and
network integrations.

## Architectural Dependencies
- **Consensus & Ledger** – The VRF consumes the Poseidon hash of the last block
  header, the active epoch identifier, and the candidate's tier seed to produce
  deterministic randomness. Consensus stores the resulting randomness, proof,
  and acceptance verdict inside `VrfSelectionRecord` entries, persisting them
  through the ledger history service.
- **Epoch Manager** – Maintains epoch boundaries, validator set rotation, and
  weighted lottery configuration. Inputs include Timetoke-derived weights,
  operator-defined target validator counts, and the epoch-level randomness
  emitted by the VRF engine.
- **Timetoke Reputation** – Provides per-identity uptime credits that feed into
  tier seeds, selection thresholds, and replay defence. Timetoke proofs update
  the `timetoke_root` commitment that consensus and proofs verify during state
  transitions.

## Poseidon Input & Output Contract
1. **Input Tuple** – The VRF preimage MUST be the ordered tuple
   `(last_block_header_hash, epoch_id, tier_seed)`. The tuple is wrapped inside
   `PoseidonVrfInput` which enforces the domain separator `POSEIDON_VRF_DOMAIN`
   and exposes helpers for hex or byte digests.
2. **Digest Computation** – `poseidon_digest_bytes()` derives the canonical
   32-byte output. All downstream components (consensus, RPC, telemetry)
   reference this digest verbatim; alternative hash implementations are not
   permitted.
3. **Proof Authoring** – `generate_vrf()` signs the digest with the node's VRF
   secret key. The resulting `VrfOutput` structure MUST include:
   - `randomness`: 32-byte Poseidon digest (for ordering candidates).
   - `proof`: Signature bytes proving knowledge of the secret key.
   - `public_key`: Affine point shared during validator registration.
4. **Verification** – `verify_vrf()` reconstructs the digest, validates the
   signature against the provided public key, and checks that the advertised
   randomness equals the canonical digest. Consensus MUST reject any submission
   that fails these checks or reuses randomness already recorded within the
   current epoch.

## Key Management Requirements
- Nodes MUST persist VRF key pairs via the configured `[secrets]` backend. The
  runtime resolves the backend at startup through
  `NodeConfig::load_or_generate_vrf_keypair`, which uses
  `FilesystemVrfKeyStore` by default and can target remote stores such as
  HashiCorp Vault without exposing secrets in logs.【F:rpp/runtime/config.rs†L567-L574】【F:rpp/runtime/config.rs†L328-L367】【F:rpp/runtime/node.rs†L611-L615】
- Operators MAY rotate keys only at epoch boundaries after broadcasting the new
  public key through the validator registration flow.
- CLI tooling continues to expose hex helpers and the filesystem helper
  `save_vrf_keypair()` for manual provisioning. When `secrets.backend =
  "filesystem"`, the key material resides at `config.vrf_key_path`; secure
  providers interpret the same field as the secret identifier within the
  external store.【F:rpp/crypto/mod.rs†L124-L167】【F:config/node.toml†L8-L13】

## Epoch Manager Responsibilities
- **Epoch Transition Scheduling** – Epochs advance when block height or wall
  clock thresholds defined in the consensus parameters are met. The manager
  triggers VRF reseeding and resets replay caches.
- **Validator Lottery** – Candidates are ranked by `(tier desc, timetoke balance
  desc, randomness asc)`. The selection threshold is derived from a smoothed
  binomial expectation that targets the operator-configured committee size.
  When submissions fall short of the target, the threshold saturates so that all
  valid candidates qualify.
- **Replay Defence** – Maintain per-epoch maps of seen randomness values and
  signed proofs. The cache clears upon epoch rollover and is persisted in the
  ledger audit trail for post-incident analysis.
- **Telemetry Hooks** – Emit epoch-level gauges (`vrf_epoch_active`,
  `vrf_epoch_target_committee`, `vrf_epoch_selected`) for dashboarding and
  alerting.

## Timetoke Data Flow & Synchronisation
1. **State Commitments** – Proof circuits and ledger metadata track the
   `timetoke_root` commitment that authenticates all reputation balances.
2. **RPC Interfaces** – Nodes expose `GET /ledger/timetoke` and
   `POST /ledger/timetoke/sync` for light clients and peers to fetch snapshots
   or submit delta batches. Requests MUST include Merkle proofs binding the
   updates to the advertised root.
3. **Gossip Distribution** – Timetoke delta payloads replicate over the
   `meta` gossip channel with fields `(identity, hours_delta, witness)` so that
  peers converge on the same root between epochs.
4. **VRF Coupling** – Epoch transitions consume the latest `timetoke_root` and
   ensure that tier seeds incorporate fresh balances. Replay protection compares
   the Timetoke version embedded in VRF submissions against the authoritative
   root; mismatches lead to rejection and audit log entries.

## Network Interfaces
### Gossip Payloads
- **Channel**: `vrf.proofs`
  - Payload: `{ epoch, round_id, validator_id, tier, timetoke_balance,
    randomness, proof_bytes }`
  - Validation: Signature verification, tier/timetoke thresholds, replay check
    against epoch cache.
- **Channel**: `meta`
  - Payload: `{ timetoke_root, snapshot_height, witness_count, checksum }`
  - Validation: Hash consistency with latest ledger commitment and proof
    inclusion for each witness.
- **Channel**: `consensus.votes`
  - Payload: Extended to include `vrf_proof_id` so consensus votes reference the
    exact randomness that promoted the proposer.

### RPC Endpoints
- `GET /status/node` – MUST include a `vrf_metrics` object with current epoch,
  submissions, acceptance ratio, fallback promotion flag, and the epoch entropy
  beacon.
- `GET /consensus/epoch/{id}/vrf-records` – Provides paginated access to
  `VrfSelectionRecord` entries for monitoring tools.
- `POST /consensus/vrf/submit` – Accepts VRF proofs from validators. Requires
  the Poseidon digest, proof bytes, validator identity, and the timetoke root
  version observed by the submitter.
- `GET /consensus/vrf/threshold` – Returns the active threshold, committee size
  target, and historical acceptance statistics for UI dashboards.

## Telemetry & Observability
- **Metrics Namespace**: `vrf.*`
  - `vrf.submissions_total{result="accepted|rejected"}` – Counter per outcome.
  - `vrf.randomness_jitter` – Histogram of randomness percentile vs. threshold.
  - `vrf.replay_blocked_total` – Counter for rejected replay attempts.
  - `vrf.timetoke_skew` – Gauge comparing min/max Timetoke balances in the
    selected committee.
- **Structured Logging**: All acceptance/rejection events MUST log `round_id`,
  `epoch`, `validator_id`, `tier`, `timetoke_balance`, `randomness`, and
  `reason` for rejection.
- **Dashboards**: Overlay VRF acceptance ratios with Timetoke accrual rates to
  correlate operator uptime with selection success. Include alerts when
  `vrf_epoch_selected` deviates from target for more than two epochs or when
  `vrf.replay_blocked_total` increments within a single epoch.

## Test Plan
### Unit Tests
- Hashing: Ensure `PoseidonVrfInput` reproduces canonical digests for known
  tuples and enforces the domain separator.
- Key Lifecycle: Verify `load_or_generate_vrf_keypair()` matches persisted
  public keys and rotates correctly at epoch boundaries.
- Threshold Logic: Model smoothed binomial expectation against representative
  Timetoke distributions to validate threshold adjustments.

### Integration Tests
- Consensus Loop: Reuse `cargo test consensus::tests:: -- --nocapture` to
  confirm validator selection, leader election, and metrics emission align with
  the spec.
- VRF Interop: Execute `cargo test tests::vrf_interop -- --nocapture` to cover
  key persistence and generate/verify round-trips using the gossip payload
  contract.
- Timetoke Sync: Drive RPC snapshot + delta round trips ensuring the VRF engine
  observes updated roots before ranking candidates.

### Replay & Fault Injection Tests
- Re-submit previously accepted proofs within the same epoch to confirm replay
  counters increment and submissions are rejected.
- Simulate stale Timetoke roots by replaying older snapshots; expect VRF
  submissions to fail root-version validation.
- Perform network-partition replays across the `meta` and `vrf.proofs` gossip
  channels to ensure caches deduplicate proofs once partitions heal.

## Review & Traceability
- Owners MUST review all VRF-related changes against this specification before
  merging. The Blueprint entry `SectionId::Vrf` links back to this document to
  maintain traceability between implementation tasks, monitoring coverage, and
  the agreed test plan.
