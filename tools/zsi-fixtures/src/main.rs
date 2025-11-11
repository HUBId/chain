#![allow(clippy::print_stdout)]

#[cfg(not(feature = "prover-stwo"))]
compile_error!("enable the `prover-stwo` feature to build the zsi-fixtures generator");

#[cfg(feature = "prover-stwo")]
use std::fs::{create_dir_all, File};
#[cfg(feature = "prover-stwo")]
use std::path::Path;

#[cfg(feature = "prover-stwo")]
use anyhow::{ensure, Context, Result};
#[cfg(feature = "prover-stwo")]
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
#[cfg(feature = "prover-stwo")]
use rpp_chain::consensus::{evaluate_vrf, BftVote, BftVoteKind, SignedBftVote};
#[cfg(feature = "prover-stwo")]
use rpp_chain::crypto::{address_from_public_key, vrf_public_key_to_hex, VrfSecretKey};
#[cfg(feature = "prover-stwo")]
use rpp_chain::ledger::{Ledger, DEFAULT_EPOCH_LENGTH};
#[cfg(feature = "prover-stwo")]
use rpp_chain::proof_backend::Blake2sHasher;
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::circuit::identity::{IdentityCircuit, IdentityWitness};
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::circuit::string_to_field;
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::fri::FriProver;
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::params::StarkParameters;
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::proof::{ProofKind, ProofPayload, StarkProof};
#[cfg(feature = "prover-stwo")]
use rpp_chain::types::{
    AttestedIdentityRequest, ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof,
    IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
};
#[cfg(feature = "prover-stwo")]
use serde_json::to_writer_pretty;

#[cfg(feature = "prover-stwo")]
fn main() -> Result<()> {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    let height = ledger.current_epoch() + 1;
    let request = build_attested_identity_request(&ledger, height)?;

    request
        .verify(
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .context("generated attested identity request failed verification")?;

    let output_dir = Path::new("tests/vectors/zsi");
    create_dir_all(output_dir).context("failed to create fixture directory")?;
    let file_path = output_dir.join("renewal_request.json");
    let file = File::create(&file_path)
        .with_context(|| format!("failed to create fixture file at {}", file_path.display()))?;
    to_writer_pretty(&file, &request).context("failed to serialize attested request")?;

    println!("wrote {}", file_path.display());
    Ok(())
}

#[cfg(feature = "prover-stwo")]
fn build_attested_identity_request(
    ledger: &Ledger,
    height: u64,
) -> Result<AttestedIdentityRequest> {
    ledger.sync_epoch_for_height(height);

    let declaration = build_identity_declaration(ledger)?;
    let identity_hash = hex::encode(declaration.hash()?);

    let voters = [seeded_keypair(10), seeded_keypair(11), seeded_keypair(12)];
    let attested_votes = voters
        .iter()
        .map(|keypair| sign_identity_vote(keypair, height, &identity_hash))
        .collect();
    let gossip_confirmations = voters
        .iter()
        .take(IDENTITY_ATTESTATION_GOSSIP_MIN)
        .map(|keypair| address_from_public_key(&keypair.public))
        .collect();

    Ok(AttestedIdentityRequest {
        declaration,
        attested_votes,
        gossip_confirmations,
    })
}

#[cfg(feature = "prover-stwo")]
fn build_identity_declaration(ledger: &Ledger) -> Result<IdentityDeclaration> {
    let pk_bytes = [1u8; 32];
    let wallet_pk = hex::encode(pk_bytes);
    let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());

    let vrf_secret = VrfSecretKey::try_from([7u8; 32])?;
    let vrf_public = vrf_secret.derive_public();
    let vrf_proof = evaluate_vrf(
        &ledger.current_epoch_nonce(),
        0,
        &wallet_addr,
        0,
        Some(&vrf_secret),
    )?;
    let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);

    let genesis = IdentityGenesis {
        wallet_pk,
        wallet_addr: wallet_addr.clone(),
        vrf_public_key: vrf_public_key_to_hex(&vrf_public),
        vrf_proof,
        epoch_nonce: hex::encode(ledger.current_epoch_nonce()),
        state_root: hex::encode(ledger.state_root()),
        identity_root: hex::encode(ledger.identity_root()),
        initial_reputation: 0,
        commitment_proof: commitment_proof.clone(),
    };

    let parameters = StarkParameters::blueprint_default();
    let commitment = genesis
        .commitment_proof
        .compute_root(&genesis.wallet_addr)
        .context("failed to compute identity commitment root")?;
    let witness = IdentityWitness {
        wallet_pk: genesis.wallet_pk.clone(),
        wallet_addr: genesis.wallet_addr.clone(),
        vrf_tag: genesis.vrf_tag().to_string(),
        epoch_nonce: genesis.epoch_nonce.clone(),
        state_root: genesis.state_root.clone(),
        identity_root: genesis.identity_root.clone(),
        initial_reputation: genesis.initial_reputation,
        commitment,
        identity_leaf: genesis.commitment_proof.leaf.clone(),
        identity_path: genesis.commitment_proof.siblings.clone(),
    };

    let circuit = IdentityCircuit::new(witness.clone());
    circuit
        .evaluate_constraints()
        .context("identity circuit constraints are not satisfied")?;
    let trace = circuit
        .generate_trace(&parameters)
        .context("failed to generate identity circuit trace")?;
    circuit
        .verify_air(&parameters, &trace)
        .context("identity air verification failed")?;

    let public_inputs = vec![
        string_to_field(&parameters, &witness.wallet_addr),
        string_to_field(&parameters, &witness.vrf_tag),
        string_to_field(&parameters, &witness.identity_root),
        string_to_field(&parameters, &witness.state_root),
    ];

    let hasher = parameters.poseidon_hasher();
    let prover = FriProver::new(&parameters);
    let air = circuit
        .define_air(&parameters, &trace)
        .context("failed to define identity air")?;
    let proof = prover.prove(&air, &trace, &public_inputs);

    let stark = StarkProof::new(
        ProofKind::Identity,
        ProofPayload::Identity(witness),
        public_inputs,
        trace,
        proof.commitment_proof,
        proof.fri_proof,
        &hasher,
    );

    let expected_commitment = genesis.expected_commitment()?;
    ensure!(
        stark.commitment == expected_commitment,
        "proof commitment mismatch: {} != {}",
        stark.commitment,
        expected_commitment
    );

    Ok(IdentityDeclaration {
        genesis,
        proof: IdentityProof {
            commitment: stark.commitment.clone(),
            zk_proof: ChainProof::Stwo(stark),
        },
    })
}

#[cfg(feature = "prover-stwo")]
fn seeded_keypair(seed: u8) -> Keypair {
    let secret = SecretKey::from_bytes(&[seed; 32]).expect("static seeds produce valid keys");
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

#[cfg(feature = "prover-stwo")]
fn sign_identity_vote(keypair: &Keypair, height: u64, identity_hash: &str) -> SignedBftVote {
    let voter = address_from_public_key(&keypair.public);
    let vote = BftVote {
        round: 0,
        height,
        block_hash: identity_hash.to_string(),
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
