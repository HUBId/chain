#![cfg(feature = "prover-stwo")]

mod fixtures;

use fixtures::{
    consensus_public_inputs, consensus_witness, consensus_witness_bytes, identity_public_inputs,
    identity_witness, identity_witness_bytes, pruning_public_inputs, pruning_witness,
    pruning_witness_bytes, recursive_public_inputs, recursive_witness, recursive_witness_bytes,
    state_public_inputs, state_witness, state_witness_bytes, uptime_public_inputs, uptime_witness,
    uptime_witness_bytes, CONSENSUS_CIRCUIT, IDENTITY_CIRCUIT, PRUNING_CIRCUIT, RECURSIVE_CIRCUIT,
    STATE_CIRCUIT, UPTIME_CIRCUIT,
};
use prover_backend_interface::ProofBackend;
use prover_backend_interface::{
    IdentityCircuitDef, ProofHeader, ProofSystemKind, PruningCircuitDef, RecursiveCircuitDef,
    StateCircuitDef, UptimeCircuitDef, WitnessHeader, PROOF_FORMAT_VERSION, WITNESS_FORMAT_VERSION,
};
use prover_stwo_backend::backend::StwoBackend;
use prover_stwo_backend::official::circuit::consensus::ConsensusWitness;
use prover_stwo_backend::official::circuit::identity::IdentityWitness;
use prover_stwo_backend::official::circuit::pruning::PruningWitness;
use prover_stwo_backend::official::circuit::recursive::RecursiveWitness;
use prover_stwo_backend::official::circuit::state::StateWitness;
use prover_stwo_backend::official::circuit::uptime::UptimeWitness;
use prover_stwo_backend::official::proof::{ProofKind, ProofPayload, StarkProof};

fn assert_witness_header(header: &WitnessHeader, circuit: &str) {
    assert_eq!(
        header.version, WITNESS_FORMAT_VERSION,
        "witness header should match the canonical format version",
    );
    assert_eq!(
        header.backend,
        ProofSystemKind::Stwo,
        "witness header should point to the STWO backend",
    );
    assert_eq!(
        header.circuit, circuit,
        "witness header should describe the expected circuit",
    );
}

fn assert_proof_header(header: &ProofHeader, circuit: &str) {
    assert_eq!(
        header.version, PROOF_FORMAT_VERSION,
        "proof header should match the canonical format version",
    );
    assert_eq!(
        header.backend,
        ProofSystemKind::Stwo,
        "proof header should point to the STWO backend",
    );
    assert_eq!(
        header.circuit, circuit,
        "proof header should describe the expected circuit",
    );
}

#[test]
fn identity_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();
    let circuit = IdentityCircuitDef::new(IDENTITY_CIRCUIT);
    let (proving_key, verifying_key) = backend
        .keygen_identity(&circuit)
        .expect("identity key generation succeeds");

    let witness = identity_witness();
    let witness_bytes = identity_witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<IdentityWitness>()
        .expect("identity witness decodes");
    assert_witness_header(&witness_header, IDENTITY_CIRCUIT);
    assert_eq!(
        decoded_witness, witness,
        "fixture identity witness should round-trip"
    );

    let proof_bytes = backend
        .prove_identity(&proving_key, &witness_bytes)
        .expect("identity proving succeeds");
    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("identity proof decodes");
    assert_proof_header(&proof_header, IDENTITY_CIRCUIT);
    assert_eq!(
        decoded_proof.kind,
        ProofKind::Identity,
        "proof should be tagged as an identity proof",
    );
    match &decoded_proof.payload {
        ProofPayload::Identity(recovered) => assert_eq!(recovered, &witness),
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = identity_public_inputs();
    backend
        .verify_identity(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("identity verification succeeds");
}

#[test]
fn state_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();
    let circuit = StateCircuitDef::new(STATE_CIRCUIT);
    let (proving_key, verifying_key) = backend
        .keygen_state(&circuit)
        .expect("state key generation succeeds");

    let witness = state_witness();
    let witness_bytes = state_witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<StateWitness>()
        .expect("state witness decodes");
    assert_witness_header(&witness_header, STATE_CIRCUIT);
    assert_eq!(decoded_witness.prev_state_root, witness.prev_state_root);

    let proof_bytes = backend
        .prove_state(&proving_key, &witness_bytes)
        .expect("state proving succeeds");
    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("state proof decodes");
    assert_proof_header(&proof_header, STATE_CIRCUIT);
    assert_eq!(decoded_proof.kind, ProofKind::State);
    match &decoded_proof.payload {
        ProofPayload::State(recovered) => {
            assert_eq!(recovered.prev_state_root, witness.prev_state_root)
        }
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = state_public_inputs();
    backend
        .verify_state(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("state verification succeeds");
}

#[test]
fn pruning_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();
    let circuit = PruningCircuitDef::new(PRUNING_CIRCUIT);
    let (proving_key, verifying_key) = backend
        .keygen_pruning(&circuit)
        .expect("pruning key generation succeeds");

    let witness = pruning_witness();
    let witness_bytes = pruning_witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<PruningWitness>()
        .expect("pruning witness decodes");
    assert_witness_header(&witness_header, PRUNING_CIRCUIT);
    assert_eq!(
        decoded_witness.removed_transactions,
        witness.removed_transactions
    );

    let proof_bytes = backend
        .prove_pruning(&proving_key, &witness_bytes)
        .expect("pruning proving succeeds");
    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("pruning proof decodes");
    assert_proof_header(&proof_header, PRUNING_CIRCUIT);
    assert_eq!(decoded_proof.kind, ProofKind::Pruning);
    match &decoded_proof.payload {
        ProofPayload::Pruning(recovered) => {
            assert_eq!(recovered.removed_transactions, witness.removed_transactions)
        }
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = pruning_public_inputs();
    backend
        .verify_pruning(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("pruning verification succeeds");
}

#[test]
fn recursive_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();
    let circuit = RecursiveCircuitDef::new(RECURSIVE_CIRCUIT);
    let (proving_key, verifying_key) = backend
        .keygen_recursive(&circuit)
        .expect("recursive key generation succeeds");

    let witness = recursive_witness();
    let witness_bytes = recursive_witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<RecursiveWitness>()
        .expect("recursive witness decodes");
    assert_witness_header(&witness_header, RECURSIVE_CIRCUIT);
    assert_eq!(
        decoded_witness.aggregated_commitment,
        witness.aggregated_commitment
    );

    let proof_bytes = backend
        .prove_recursive(&proving_key, &witness_bytes)
        .expect("recursive proving succeeds");
    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("recursive proof decodes");
    assert_proof_header(&proof_header, RECURSIVE_CIRCUIT);
    assert_eq!(decoded_proof.kind, ProofKind::Recursive);
    match &decoded_proof.payload {
        ProofPayload::Recursive(recovered) => {
            assert_eq!(
                recovered.aggregated_commitment,
                witness.aggregated_commitment
            )
        }
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = recursive_public_inputs();
    backend
        .verify_recursive(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("recursive verification succeeds");
}

#[test]
fn uptime_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();
    let circuit = UptimeCircuitDef::new(UPTIME_CIRCUIT);
    let (proving_key, verifying_key) = backend
        .keygen_uptime(&circuit)
        .expect("uptime key generation succeeds");

    let witness = uptime_witness();
    let witness_bytes = uptime_witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<UptimeWitness>()
        .expect("uptime witness decodes");
    assert_witness_header(&witness_header, UPTIME_CIRCUIT);
    assert_eq!(decoded_witness.commitment, witness.commitment);

    let proof_bytes = backend
        .prove_uptime(&proving_key, &witness_bytes)
        .expect("uptime proving succeeds");
    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("uptime proof decodes");
    assert_proof_header(&proof_header, UPTIME_CIRCUIT);
    assert_eq!(decoded_proof.kind, ProofKind::Uptime);
    match &decoded_proof.payload {
        ProofPayload::Uptime(recovered) => assert_eq!(recovered.commitment, witness.commitment),
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = uptime_public_inputs();
    backend
        .verify_uptime(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("uptime verification succeeds");
}

#[test]
fn consensus_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();

    let witness = consensus_witness();
    let witness_bytes = consensus_witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<ConsensusWitness>()
        .expect("consensus witness decodes");
    assert_witness_header(&witness_header, CONSENSUS_CIRCUIT);
    assert_eq!(decoded_witness.block_hash, witness.block_hash);

    let (proof_bytes, verifying_key, circuit) = backend
        .prove_consensus(&witness_bytes)
        .expect("consensus proving succeeds");
    assert_eq!(circuit.identifier, CONSENSUS_CIRCUIT);

    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("consensus proof decodes");
    assert_proof_header(&proof_header, CONSENSUS_CIRCUIT);
    assert_eq!(decoded_proof.kind, ProofKind::Consensus);
    match &decoded_proof.payload {
        ProofPayload::Consensus(recovered) => {
            assert_eq!(recovered.quorum_threshold, witness.quorum_threshold)
        }
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = consensus_public_inputs();
    backend
        .verify_consensus(&verifying_key, &proof_bytes, &circuit, &expected_inputs)
        .expect("consensus verification succeeds");
}
