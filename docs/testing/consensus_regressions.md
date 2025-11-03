# Consensus Proof Regression Catalog

This catalog tracks regression tests that protect the consensus proof pipeline.
Each entry records the intent of the test and the current outcome.

| Scenario | STWO backend | Plonky3 backend | Gap |
| --- | --- | --- | --- |
| VRF commitment tampering | ✅ `consensus_verification_rejects_vrf_tampering` | ❌ [`TODO: consensus_verification_rejects_plonky3_vrf_tampering`](../../prover/plonky3_backend/tests/consensus_vrf_tampering.rs) | Port STWO VRF tamper to Plonky3 harness to close backend parity. |
| Quorum bitmap tampering | ✅ `consensus_verification_rejects_quorum_bitmap_tampering` | ❌ [`TODO: consensus_verification_rejects_plonky3_quorum_tampering`](../../prover/plonky3_backend/tests/consensus_quorum_tampering.rs) | Plonky3 rejection wiring missing; track until tests land. |

✅ in the STWO column denotes shipped coverage in `prover/prover_stwo_backend`, executed with
`cargo test -p prover-stwo-backend`. The Plonky3 TODOs track the follow-up harness expected in
`prover/plonky3_backend/tests/consensus_vrf_tampering.rs` and
`prover/plonky3_backend/tests/consensus_quorum_tampering.rs` respectively. Once those tests
land—and the ❌ entries flip to ✅—both backends will reject identical tampering mutations during
the regression sweep.

The STWO suite lives in `prover/prover_stwo_backend` and runs with
`cargo test -p prover-stwo-backend`.【F:prover/prover_stwo_backend/src/backend.rs†L1193-L1334】
Plonky3 currently exercises consensus verification via `prover/plonky3_backend/tests/consensus.rs`,
but the tamper regression slots above remain TODO until the dedicated files land.【F:prover/plonky3_backend/tests/consensus.rs†L1-L176】

All four scenarios are wired into the Phase 2 test matrix via
`cargo xtask test-consensus-manipulation`—set `XTASK_FEATURES="backend-plonky3"` to
execute both backend suites in one run.【F:xtask/src/main.rs†L70-L123】
