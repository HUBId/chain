use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use hex;

use rpp_chain::consensus::{BftVote, BftVoteKind, SignedBftVote};
use rpp_chain::crypto::{address_from_public_key, generate_vrf_keypair, vrf_public_key_to_hex};
use rpp_chain::ledger::{DEFAULT_EPOCH_LENGTH, Ledger};
use rpp_chain::stwo::circuit::StarkCircuit;
use rpp_chain::stwo::circuit::identity::{IdentityCircuit, IdentityWitness};
use rpp_chain::stwo::circuit::string_to_field;
use rpp_chain::stwo::fri::FriProver;
use rpp_chain::stwo::params::StarkParameters;
use rpp_chain::stwo::proof::{ProofKind, ProofPayload, StarkProof};
use rpp_chain::types::{
    AttestedIdentityRequest, ChainProof, IDENTITY_ATTESTATION_GOSSIP_MIN,
    IDENTITY_ATTESTATION_QUORUM, IdentityDeclaration, IdentityGenesis, IdentityProof,
};

fn seeded_keypair(seed: u8) -> Keypair {
    let secret = SecretKey::from_bytes(&[seed; 32]).expect("secret");
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

fn sign_identity_vote(keypair: &Keypair, height: u64, hash: &str) -> SignedBftVote {
    let voter = address_from_public_key(&keypair.public);
    let vote = BftVote {
        round: 0,
        height,
        block_hash: hash.to_string(),
        voter: voter.clone(),
        kind: BftVoteKind::PreCommit,
    };
    let signature = keypair.sign(&vote.message_bytes());
    SignedBftVote {
        vote,
        public_key: hex::encode(keypair.public.to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    }
}

fn sample_identity_declaration(ledger: &Ledger) -> IdentityDeclaration {
    ledger.sync_epoch_for_height(1);
    let pk_bytes = vec![1u8; 32];
    let pk_hex = hex::encode(&pk_bytes);
    let wallet_addr = hex::encode::<[u8; 32]>(
        stwo::core::vcs::blake2_hash::Blake2sHasher::hash(&pk_bytes).into(),
    );
    let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
    let vrf = rpp_chain::consensus::evaluate_vrf(
        &ledger.current_epoch_nonce(),
        0,
        &wallet_addr,
        0,
        Some(&vrf_keypair.secret),
    )
    .expect("evaluate vrf");
    let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
    let genesis = IdentityGenesis {
        wallet_pk: pk_hex,
        wallet_addr: wallet_addr.clone(),
        vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
        vrf_proof: vrf.clone(),
        epoch_nonce: hex::encode(ledger.current_epoch_nonce()),
        state_root: hex::encode(ledger.state_root()),
        identity_root: hex::encode(ledger.identity_root()),
        initial_reputation: 0,
        commitment_proof: commitment_proof.clone(),
    };

    let parameters = StarkParameters::blueprint_default();
    let expected_commitment = genesis.expected_commitment().expect("expected commitment");
    let witness = IdentityWitness {
        wallet_pk: genesis.wallet_pk.clone(),
        wallet_addr: genesis.wallet_addr.clone(),
        vrf_tag: genesis.vrf_tag().to_string(),
        epoch_nonce: genesis.epoch_nonce.clone(),
        state_root: genesis.state_root.clone(),
        identity_root: genesis.identity_root.clone(),
        initial_reputation: genesis.initial_reputation,
        commitment: genesis
            .commitment_proof
            .compute_root(&genesis.wallet_addr)
            .expect("commitment root"),
        identity_leaf: genesis.commitment_proof.leaf.clone(),
        identity_path: genesis.commitment_proof.siblings.clone(),
    };
    let circuit = IdentityCircuit::new(witness.clone());
    circuit
        .evaluate_constraints()
        .expect("constraints satisfied");
    let trace = circuit.generate_trace(&parameters).expect("trace");
    circuit.verify_air(&parameters, &trace).expect("air");
    let inputs = vec![
        string_to_field(&parameters, &witness.wallet_addr),
        string_to_field(&parameters, &witness.vrf_tag),
        string_to_field(&parameters, &witness.identity_root),
        string_to_field(&parameters, &witness.state_root),
    ];
    let hasher = parameters.poseidon_hasher();
    let prover = FriProver::new(&parameters);
    let air = circuit
        .define_air(&parameters, &trace)
        .expect("air definition");
    let proof = prover.prove(&air, &trace, &inputs);
    let stark = StarkProof::new(
        ProofKind::Identity,
        ProofPayload::Identity(witness),
        inputs,
        trace,
        proof.commitment_proof,
        proof.fri_proof,
        &hasher,
    );
    IdentityDeclaration {
        genesis,
        proof: IdentityProof {
            commitment: expected_commitment,
            zk_proof: ChainProof::Stwo(stark),
        },
    }
}

#[test]
#[ignore]
fn zsi_identity_submission_requires_bft_attestation() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    let declaration = sample_identity_declaration(&ledger);
    let identity_hash = hex::encode(declaration.hash().expect("hash"));
    let height = ledger.current_epoch() + 1;
    let voters = vec![seeded_keypair(10), seeded_keypair(11), seeded_keypair(12)];
    let attested_votes: Vec<SignedBftVote> = voters
        .iter()
        .map(|kp| sign_identity_vote(kp, height, &identity_hash))
        .collect();
    let gossip_confirmations = voters
        .iter()
        .take(2)
        .map(|kp| address_from_public_key(&kp.public))
        .collect();
    let request = AttestedIdentityRequest {
        declaration,
        attested_votes,
        gossip_confirmations,
    };

    request
        .verify(
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("attestation should satisfy quorum");
    ledger
        .register_identity(
            &request,
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("ledger registers attested identity");
}

#[test]
#[ignore]
fn zsi_identity_submission_slashes_on_invalid_vote() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    let declaration = sample_identity_declaration(&ledger);
    let identity_hash = hex::encode(declaration.hash().expect("hash"));
    let height = ledger.current_epoch() + 1;
    let voters = vec![seeded_keypair(20), seeded_keypair(21), seeded_keypair(22)];
    let mut attested_votes: Vec<SignedBftVote> = voters
        .iter()
        .map(|kp| sign_identity_vote(kp, height, &identity_hash))
        .collect();
    attested_votes[2].vote.height = height + 1;
    let gossip_confirmations = voters
        .iter()
        .take(2)
        .map(|kp| address_from_public_key(&kp.public))
        .collect();
    let request = AttestedIdentityRequest {
        declaration,
        attested_votes,
        gossip_confirmations,
    };

    let err = request
        .verify(
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect_err("invalid attestation rejected");
    assert!(matches!(err, rpp_chain::errors::ChainError::Transaction(_)));
    // Slashing is handled by the node runtime; the ledger should remain unchanged for invalid requests.
    assert!(ledger.slashing_events(10).is_empty());
    // Ensure ledger state unaffected.
    assert!(
        ledger
            .get_account(&request.declaration.genesis.wallet_addr)
            .is_none()
    );
}
