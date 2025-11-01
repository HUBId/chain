# Poseidon VRF Developer Notes

## Overview
The VRF engine derives deterministic yet unpredictable randomness from the
Poseidon hash of the last block header, the active epoch identifier, and a
tier-specific seed. The resulting digest is signed with the node's VRF secret
key to produce both the verifiable proof bytes and a 32-byte randomness value
that consensus routines can rank deterministically.

> **⚠️ Production warning:** Validator deployments must continue to ship with the
> STWO prover backend (`--no-default-features --features prod,prover-stwo` or
> `prover-stwo-simd`). The experimental `backend-plonky3` feature is blocked in
> production: the crate refuses to compile when the stub is paired with the
> `prod` or `validator` feature sets, the release scripts halt if any Plonky3
> alias slips into the build, and runtime bootstrap rejects validator or hybrid
> modes unless the STWO backend is present. Review the release pipeline
> checklist before promoting binaries so these guardrails are always verified.
> [`feature_guard.rs`](../rpp/node/src/feature_guard.rs) ·
> [`build_release.sh`](../scripts/build_release.sh) ·
> [`verify_release_features.sh`](../scripts/verify_release_features.sh) ·
> [`ensure_prover_backend`](../rpp/node/src/lib.rs) ·
> [Release pipeline checklist](../RELEASE.md#release-pipeline-checklist)

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
publishes the digest itself as the 32-byte randomness field. The companion
`verify_vrf` routine reconstructs the digest, validates the signature with the
public key, and ensures the advertised randomness matches the canonical
Poseidon output. `VrfOutput` keeps the randomness and proof in fixed-size
arrays and supplies parsing helpers to rebuild outputs from byte or hex
encodings.

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

These helpers are shipped in-tree through `rpp/crypto-vrf` and the runtime's
crypto wrapper so nodes can manage Poseidon VRF material without external
tooling.【F:rpp/crypto-vrf/src/lib.rs†L247-L360】【F:rpp/crypto/mod.rs†L542-L575】

## Epoch management & thresholding

`VrfEpochManager` rotates epochs, deduplicates submissions, and carries the
entropy beacon forward, while `select_validators` executes the weighted lottery
and fallback selection defined in the blueprint. Together they provide the
replay protection, per-epoch thresholds, and audit data that consensus consumes
when finalising validator sets.【F:rpp/crypto-vrf/src/lib.rs†L648-L999】

## Consensus Integration
Consensus evaluation paths request Poseidon-backed proofs when VRF key material
is available and fall back to computing the raw digest only when no secret key
is supplied (for example during identity registration). Successful Poseidon
evaluations retain the randomness and proof bytes so validator threshold checks
and proposer selection can operate without any extra conversions. Verification
requires the published proof to verify against the signer’s VRF public key and
no longer accepts legacy Blake2s fallbacks, ensuring replayed hashes cannot
masquerade as valid proofs.

Validator thresholds are now computed per epoch by combining the epoch number,
each candidate's tier seed, and the operator-defined target validator count.
Every epoch collects the observed randomness values, blends a smoothed
binomial expectation with the per-epoch quantile for the target committee size,
and produces a jittered threshold so the expected validator population tracks
the desired size even when participation swings sharply. When the target
exceeds the number of submissions, the threshold saturates so every participant
qualifies; otherwise the deterministic jitter keeps similarly seeded nodes from
repeatedly colliding on the cutoff.

`ConsensusRound::new` wires those helpers directly, persisting the VRF audit
trail and metrics that the runtime later publishes via its status endpoints, so
no additional adapter crate is required.【F:rpp/consensus/node.rs†L360-L450】

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
Use the integrated validator CLI to rotate, audit, and export Poseidon VRF
material. `rpp-node validator vrf rotate` provisions a fresh keypair through the
secrets backend declared in the validator configuration, reports the resolved
storage identifier, and overwrites any existing entry in the same location.【F:rpp/node/src/main.rs†L250-L288】

Common invocations mirror the operator guide and pass an explicit configuration
path when the node is not using the default `config/validator.toml` profile. The
CLI automatically falls back to that path when `--config` is omitted.【F:rpp/node/src/main.rs†L22-L113】【F:docs/rpp_node_operator_guide.md†L40-L66】

```sh
# Rotate VRF keys in place using the filesystem-backed secrets store
rpp-node validator vrf rotate --config config/validator.toml

# Inspect the stored keypair after migrating to a Vault backend
rpp-node validator vrf inspect --config /etc/rpp/validator.toml

# Export the active keypair to a JSON bundle for backup procedures
rpp-node validator vrf export --config /etc/rpp/validator.toml --output ./backups/validator-vrf.json
```

The CLI resolves the configured secrets backend, ensures the target directory or
remote identifier exists, and then loads or persists the VRF material through
the same abstraction that the runtime uses at startup.【F:rpp/node/src/main.rs†L264-L345】【F:rpp/node/src/main.rs†L555-L568】【F:rpp/runtime/config.rs†L1398-L1401】

Tune VRF persistence and committee sizing directly in the validator
configuration. `NodeConfig` exposes the `vrf_key_path` and `secrets` block that
drive the keystore lookup, while `target_validator_count` continues to control
the per-epoch selection threshold. The repository ships a reference profile in
`config/node.toml` that illustrates the default filesystem layout and telemetry
settings for operators to extend.【F:rpp/runtime/config.rs†L1131-L1175】【F:rpp/runtime/config.rs†L1350-L1401】【F:config/node.toml†L1-L24】

For end-to-end runbooks—including how to stage Vault credentials, validate
telemetry, and capture CLI output for audits—consult the `rpp-node` operator
guide and the validator tooling companion reference.【F:docs/rpp_node_operator_guide.md†L46-L66】

## Telemetry & Metrics
`GET /status/node` now surfaces a `vrf_metrics` payload containing the submission
pool size, verified/accepted counts, rejection totals, and whether a fallback
validator was promoted in the last round. The payload also reports participation
rate, the cumulative validator weight, and the epoch entropy beacon produced by
the VRF epoch manager so operators can chart fairness and randomness drift
alongside consensus and mempool health.【F:rpp/runtime/node.rs†L3921-L3936】

Metrics are exported directly from `select_validators` through the
`rpp.crypto_vrf.selection.*` instruments so dashboards can track pool health and
threshold behaviour without polling RPCs.【F:rpp/crypto-vrf/src/telemetry.rs†L1-L123】【F:rpp/crypto-vrf/src/lib.rs†L821-L999】
Telemetry streaming remains gated by `rollout.telemetry.*` in `config/node.toml`,
and the VRF-specific alert thresholds can be tuned under
`rollout.telemetry.vrf_thresholds`. The `docs/observability/vrf.md` blueprint
packages recommended panels and alert rules for operators to adopt alongside the
existing troubleshooting guide.【F:config/node.toml†L62-L88】【F:docs/observability/vrf.md†L1-L64】【F:docs/validator_troubleshooting.md†L9-L38】

## Testing Guidance
Run `cargo test vrf::tests` to exercise the Poseidon digest helpers, VRF
round-trip verification, and key lifecycle regression coverage. Run
`cargo test consensus::tests:: -- --nocapture` to cover validator selection,
leader election, and VRF metrics reporting at the consensus layer. The
`tests/vrf_interop.rs` integration test reloads persisted keys and validates a
full generate/verify cycle using the same helper APIs as consensus.
