# Fuzzing RPP Chain Components

This repository now ships with a `cargo-fuzz` workspace under `fuzz/` that exercises
high-value parsing and verification entry points. Each target consumes structured
inputs (JSON or TOML) so that corpora and dictionaries remain human-readable.

## Targets

| Target | Entry point | Notes |
| ------ | ----------- | ----- |
| `transaction_parser` | `rpp_chain::sync::RuntimeTransactionProofVerifier::verify` | Decodes gossip transaction bundles and performs signature/proof integrity checks. |
| `network_messages` | `rpp_p2p::pipeline::LightClientSync::{ingest_plan, ingest_light_client_update, ingest_chunk}` | Covers state sync plan decoding, recursive proof validation, and chunk ingestion. |
| `pruning_proof` | `rpp_chain::types::PruningProof::verify` | Validates pruning proofs against supplied block headers and (optional) previous blocks. |
| `config_loader` | `rpp_chain::config::NodeConfig` + `NodeConfig::validate` | Exercises TOML parsing and semantic validation of node configuration. |

Seed corpora live under `fuzz/corpus/<target>/` with matching dictionaries in
`fuzz/dictionaries/<target>.dict`. They encode common field names and example
payloads to keep coverage high from the first iteration.

## CI Smoke Runs

`scripts/ci/fuzz-smoke.sh` executes a short (≈45s) run for every target using a
fixed seed to keep CI deterministic. The workflow `.github/workflows/fuzz-smoke.yml`
invokes this script on pushes to `main` and on pull requests. Crash artifacts, if
any, are stored beneath `fuzz/artifacts/<target>-*` so the CI job can surface them.

To reproduce the CI job locally:

```bash
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked
scripts/ci/fuzz-smoke.sh
```

## Longer Local Sessions

For exploratory fuzzing you can extend the runtime and adjust seeds. Examples:

```bash
cd fuzz
cargo +nightly fuzz run transaction_parser corpus/transaction_parser \
  -- -dict=dictionaries/transaction_parser.dict -max_total_time=600 -artifact_prefix=artifacts/transaction_parser-

cargo +nightly fuzz run pruning_proof corpus/pruning_proof \
  -- -dict=dictionaries/pruning_proof.dict -max_total_time=900 -seed=0xDEADBEEF
```

Artifacts remain in `fuzz/artifacts/` and corpora are automatically updated when
new interesting inputs are discovered. Remember to sync useful additions back to
the repository when they materially improve coverage.
