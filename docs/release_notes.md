# Release notes with proof metadata

This document records release-specific proof metadata for the Malachite Phase 2 program. Every section below is sourced from `cargo xtask proof-metadata --format markdown` so auditors can compare circuit fingerprints, constraint counts, and backend coverage for a given release. Re-run the command during the release process to refresh the tables before tagging a build.

## Unreleased

### Highlights
- Simnet regression harness runs the Phase 2 VRF/quorum stress, snapshot rebuild, and gossip backpressure scenarios in sequence and publishes aggregate HTML/JSON reports for CI and nightly jobs.
- VRF/quorum observability playbook defines actionable alert thresholds, escalation paths, and references the new dashboards for on-call teams.
- Release automation now injects proof metadata into generated notes, capturing Plonky3 verifying/proving keys, STWO verifying key commitments, and blueprint circuit stages.
- Release packaging emits `snapshot-manifest-summary-<target>.json` whenever pruning snapshots are attached to a build. The summary lists the snapshot manifest identifier, recorded Firewood state root, and chunk count derived from the persisted state-sync plan so operators can validate bundle integrity before rollout.【F:scripts/generate_snapshot_summary.py†L1-L190】【F:scripts/build_release.sh†L258-L272】【F:.github/workflows/release.yml†L275-L295】
- Snapshot & Timetoke automation is documented in the test strategy, adds the `observability-metrics` gate to Branch-Protection, and ships new Prometheus rules (`SnapshotManifestSignatureInvalid`, `SnapshotReplayStallCritical`, `SnapshotChecksumDrift`) together with nightly artefacts (`snapshot-health-report.json`, `timetoke-slo-report.md`).【F:docs/test_validation_strategy.md†L128-L174】【F:.github/workflows/ci.yml†L412-L446】【F:docs/observability/alerts/snapshot_manifest.yaml†L1-L52】【F:.github/workflows/nightly.yml†L29-L124】

### Proof metadata

# Proof metadata summary

## Plonky3 circuits

| Circuit | Verifying key (BLAKE3) | Bytes | Proving key (BLAKE3) | Bytes |
| --- | --- | ---: | --- | ---: |
| consensus | `92714c6f3473be80b07b28428008fb0bc966cf5b2f62c4efb5ab9fbcac9ceea8` | 96 | `1ffea21db7a7ca3971f91a41217a8f9d76b6c972bb6f163ff8c85359ab503231` | 320 |
| identity | `3e1233f18086abbb937e96094a5ed3e54ef694154cf507458ba2bc19e65cf8c3` | 96 | `461f400982b11e014dcf031ad614b6a6e7cddfc12e1551b77eb358c65abc5349` | 192 |
| pruning | `2d446f003445c6e18207faa43166f168654a1e94bdb07ac67e6dda5250840e2f` | 96 | `021ae3e4b8418bd8485649f4c66069b063970b41dfdda60ce8d9aa64f192b89e` | 160 |
| recursive | `4bff41c76f6ccd898e07db2dae4464640402bbe80fc6aa1457e96c13c9eead6b` | 96 | `62195abd9a0e94ce67e7e0fda972367ea4b6e2dfc3c895f32a2d37b497b7dd20` | 288 |
| state | `b8b7ec60e5f4c1bbdd295ed592783a72a92a4966c99bc8beaea7f259866eb280` | 96 | `2a63ae9d8993bf464229c725e7706290a6f24bd8fd9460afdb5739021639ae90` | 224 |
| transaction | `f4495a89cdd7974d71469526b111eba6c390d7567f9d64f26fe7771ffb9ae702` | 96 | `058b95c7fb8612da8baa52ad5c13b8ff79a238caa8bf50fe1b85eb8b47cc98b` | 256 |
| uptime | `7a015dcee33b1262412ddd008d207117ee865257d16f0ca180b0f05b5eedbc48` | 96 | `8c42953069d1b90ab000ebecaa6e724bca80d5fa59d9947003fac4f7a0b251e6` | 128 |

## STWO circuits

| Circuit | Degree | Commitment |
| --- | ---: | --- |
| block | 2048 | `block-vk-0001` |
| identity | 256 | `id-vk-0001` |
| reputation | 512 | `rep-vk-0001` |
| transaction | 1024 | `tx-vk-0001` |

## Blueprint stages

| Stage | Kind | Proof system | Constraints | Description |
| --- | --- | --- | ---: | --- |
| block_transition_aggregation | aggregation | stwo | 3 | Aggregates all module digests, binds them to the block header and exposes the proof registry root. |
| consensus_attestation | base | stwo | 3 | Validates Malachite BFT votes and quorum signatures for the proposed block. |
| global_state_transition | base | stwo | 3 | Applies account-level balance, stake and nonce updates while linking to the global state commitment. |
| recursive_wrapper | recursion | plonky2 | 3 | Wraps the STWO block proof and the previous recursive accumulator into a succinct proof chain. |
| reputation_update | base | stwo | 3 | Aggregates timetoke rewards, consensus participation and penalties into updated reputation tiers. |
| timetoke_accrual | base | stwo | 3 | Checks epoch-bounded uptime proofs and updates timetoke balances. |
| utxo_transition | base | stwo | 3 | Validates consumption and creation of UTXOs across the transaction batch. |
| zsi_onboarding | base | stwo | 3 | Proves correct inclusion of newly approved zero-state identities. |

### Supported backends
- **STWO** provides the base and aggregation circuits listed above.
- **Plonky2** wraps the recursive accumulator for proof chaining.

## Phase 2 Completed (2026-04-15)

### Stakeholder summary
- Proof-hardening milestones ENG‑742 und ENG‑743 sind ausgeliefert; STWO und Plonky3 berechnen VRF-/Quorum-Transkripte deterministisch nach und dokumentieren die Constraint-Layouts über `cargo xtask proof-metadata`.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L300-L586】【F:prover/plonky3_backend/src/circuits/consensus.rs†L520-L690】【F:docs/release_notes.md†L1-L120】
- Branch-Protections `unit-suites`, `integration-workflows` und `simnet-smoke` sichern jede Änderung mit vollständiger Feature-Matrix ab; Nightly-Jobs halten die Matrix grün und veröffentlichen Simnet-Artefakte.【F:.github/workflows/ci.yml†L185-L303】【F:.github/workflows/nightly.yml†L88-L183】
- Observability-Deliverables (Dashboards, Alerts, Runbooks) tracken VRF-Latenzen, Quorum-Verifikationen und Eskalationspfade für On-Call-Teams.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】【F:docs/runbooks/observability.md†L1-L160】

### Next steps
- Prepare Phase 3 networking scope (Snapshot-Verteilung, Witness-Gossip) as outlined in the roadmap implementation plan Sections 2, 4.2, 4.3 and 6.4/6.5.

