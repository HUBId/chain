use prover_stwo_circuits::circuits::balance::{AccountSnapshot, BalanceWitness};
use prover_stwo_circuits::circuits::double_spend::{DoubleSpendWitness, OutpointWitness};
use prover_stwo_circuits::circuits::tier_attestation::{TierAttestationWitness, TierLevel};
use prover_stwo_circuits::{
    build_balance_circuit, build_double_spend_circuit, build_tier_attestation_circuit, CircuitError,
};

#[test]
fn balance_witness_matches_blueprint_expectations() {
    let sender_before = AccountSnapshot::new("alice", 1_000, 7);
    let sender_after = AccountSnapshot::new("alice", 850, 8);
    let recipient_before = Some(AccountSnapshot::new("bob", 125, 4));
    let recipient_after = AccountSnapshot::new("bob", 275, 4);
    let witness = BalanceWitness::new(sender_before, sender_after, recipient_before, recipient_after, 150, 0);

    let circuit = build_balance_circuit(witness).expect("construct balance circuit");
    assert!(circuit.verify().is_ok(), "balance circuit should pass");
}

#[test]
fn balance_circuit_detects_incorrect_sender_delta() {
    let sender_before = AccountSnapshot::new("alice", 100, 1);
    let sender_after = AccountSnapshot::new("alice", 10, 2);
    let recipient_after = AccountSnapshot::new("bob", 50, 0);
    let witness = BalanceWitness::new(sender_before, sender_after, None, recipient_after, 70, 0);

    let circuit = build_balance_circuit(witness).expect("construct balance circuit");
    let err = circuit.verify().expect_err("balance mismatch should fail");
    assert!(matches!(err, CircuitError::ConstraintViolation(_)));
}

#[test]
fn double_spend_circuit_catches_reintroduced_inputs() {
    let available = vec![OutpointWitness::new("tx-a", 0), OutpointWitness::new("tx-b", 1)];
    let consumed = vec![OutpointWitness::new("tx-a", 0)];
    let produced = vec![OutpointWitness::new("tx-a", 0)];
    let witness = DoubleSpendWitness::new(available, consumed, produced);

    let circuit = build_double_spend_circuit(witness).expect("construct double spend circuit");
    let err = circuit.verify().expect_err("double spend should fail");
    assert!(matches!(err, CircuitError::ConstraintViolation(_)));
}

#[test]
fn double_spend_circuit_accepts_unique_inputs() {
    let available = vec![OutpointWitness::new("tx-a", 0), OutpointWitness::new("tx-b", 1)];
    let consumed = vec![OutpointWitness::new("tx-a", 0)];
    let produced = vec![OutpointWitness::new("tx-c", 0)];
    let witness = DoubleSpendWitness::new(available, consumed, produced);

    let circuit = build_double_spend_circuit(witness).expect("construct double spend circuit");
    assert!(circuit.verify().is_ok(), "double spend circuit should succeed");
}

#[test]
fn tier_attestation_circuit_enforces_threshold() {
    let witness = TierAttestationWitness::new(
        "wallet-1",
        TierLevel::Tl2,
        TierLevel::Tl3,
        true,
        "digest",
    );
    let circuit = build_tier_attestation_circuit(witness).expect("construct tier circuit");
    let err = circuit.verify().expect_err("tier mismatch should fail");
    assert!(matches!(err, CircuitError::ConstraintViolation(_)));
}

#[test]
fn tier_attestation_accepts_valid_signature_and_rank() {
    let witness = TierAttestationWitness::new(
        "wallet-99",
        TierLevel::Tl4,
        TierLevel::Tl3,
        true,
        "digest",
    );
    let circuit = build_tier_attestation_circuit(witness).expect("construct tier circuit");
    assert!(circuit.verify().is_ok(), "tier attestation should pass");
}
