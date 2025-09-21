# Poseidon VRF Developer Notes

## Overview
The VRF engine derives deterministic yet unpredictable randomness from the
Poseidon hash of the last block header, the active epoch identifier, and a
tier-specific seed. The resulting digest is signed with the node's VRF secret
key to produce both the verifiable proof bytes and a 32-byte randomness value
that consensus routines can rank deterministically.

## Poseidon Input Tuple
The `PoseidonVrfInput` struct captures the blueprint-mandated tuple and exposes
helpers for digest construction:

- `PoseidonVrfInput::new` wires the `(last_block_header, epoch, tier_seed)`
  tuple into the domain-specific wrapper.
- `poseidon_digest_bytes` and `poseidon_digest_hex` compute the canonical
  Poseidon output for downstream consumers without reimplementing sponge
  arithmetic.
- `POSEIDON_VRF_DOMAIN` scopes the hash preimage to the VRF module so other
  Poseidon usages cannot collide with validator selection inputs.

## VRF Proof Generation & Verification
`generate_vrf` signs the Poseidon digest with the node's VRF secret key and
hashes the signature bytes via Blake2s to derive the randomness field. The
companion `verify_vrf` routine reconstructs the digest, validates the signature
with the public key, and re-hashes the proof bytes to ensure the published
randomness matches the canonical value. `VrfOutput` keeps the randomness and
proof in fixed-size arrays and supplies parsing helpers to rebuild outputs from
byte or hex encodings.

## Key Management
The crypto module owns the VRF key lifecycle:

- `generate_vrf_keypair` samples a 32-byte secret and derives the matching
  public key.
- `save_vrf_keypair` persists the material as hex-encoded TOML so operators can
  version the keys alongside other node secrets.
- `load_vrf_keypair` and `load_or_generate_vrf_keypair` restore existing keys,
  verify that the stored public key matches the regenerated value from the
  secret, and optionally create new pairs when none exist.
- Hex helpers (`vrf_public_key_to_hex`, `vrf_secret_key_to_hex`, and their
  parsing counterparts) ease CLI and configuration plumbing.

## Consensus Integration
Consensus evaluation paths request Poseidon-backed proofs when VRF key material
is available and fall back to the legacy Blake2s hash otherwise. Successful
Poseidon evaluations retain the randomness and proof bytes so validator
threshold checks and proposer selection can operate without any extra
conversions. Verification applies the same strategy: attempt cryptographic
validation first, log failures, and finally compare against the deterministic
hash fallback to preserve backward compatibility.

Validator thresholds are now computed per epoch by combining the epoch number,
each candidate's tier seed, and the operator-defined target validator count.
Every epoch collects the observed randomness values, blends a smoothed
binomial expectation with the per-epoch quantile for the target committee size,
and produces a jittered threshold so the expected validator population tracks
the desired size even when participation swings sharply. When the target
exceeds the number of submissions, the threshold saturates so every participant
qualifies; otherwise the deterministic jitter keeps similarly seeded nodes from
repeatedly colliding on the cutoff.

## Audit Trail & History
Consensus rounds now emit structured `VrfSelectionRecord` entries that capture
the address, tier, timetoke balance, published proof, and the final verdict for
every submission. Nodes persist those records via `Ledger::record_vrf_history`
which deduplicates proofs per epoch, stores them alongside the consensus
round, and exposes query helpers so operators can audit validator selection
long after a block was sealed. The ledger also maintains a per-epoch VRF tag
set through `register_vrf_tag` to guard against duplicated proofs entering the
history or being reused during identity onboarding.

## CLI & Configuration
`cargo run -- keygen` now emits both the Ed25519 identity keypair and a VRF
keypair. Nodes read the VRF file from `config.vrf_key_path` during startup,
creating it on demand when operators have not provisioned one yet. The
`target_validator_count` configuration entry drives the dynamic threshold used
for per-epoch validator selection.

## Telemetry & Metrics
`GET /status/node` now surfaces a `vrf_metrics` payload containing the submission
pool size, verified/accepted counts, rejection totals, and whether a fallback
validator was promoted in the last round. Telemetry snapshots include the same
structure so operators can chart VRF participation rates alongside consensus
and mempool health.

## Testing Guidance
Run `cargo test vrf::tests` to exercise the Poseidon digest helpers, VRF
round-trip verification, and key lifecycle regression coverage. Run
`cargo test consensus::tests:: -- --nocapture` to cover validator selection,
leader election, and VRF metrics reporting at the consensus layer. The
`tests/vrf_interop.rs` integration test reloads persisted keys and validates a
full generate/verify cycle using the same helper APIs as consensus.
