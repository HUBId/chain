use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};

use rpp_chain::consensus::{
    evaluate_vrf, BftVote, BftVoteKind, ConsensusRound, ObserverProfile, SignedBftVote,
    ValidatorCandidate,
};
use rpp_chain::crypto::{
    address_from_public_key, load_keypair, load_vrf_keypair, sign_message, signature_to_hex,
    VrfKeypair,
};
use rpp_chain::types::block::Block;
use rpp_chain::vrf::{derive_tier_seed, PoseidonVrfInput, VrfSubmission, VrfSubmissionPool};

use super::cluster::TestClusterNode;

/// Reconstructs the [`ConsensusRound`] context used to produce the provided `block`.
///
/// The supplied `block` must expose the height, round and block hash that match the
/// target consensus step. The caller is responsible for passing all validators that
/// participated in the round via `participants` so that VRF submissions can be rebuilt
/// from their key material.
pub fn consensus_round_for_block(
    node: &TestClusterNode,
    block: &Block,
    participants: &[TestClusterNode],
) -> Result<ConsensusRound> {
    let membership = node
        .node_handle
        .bft_membership()
        .context("failed to query BFT membership")?;

    let mut seed = [0u8; 32];
    if !block.header.previous_hash.is_empty() {
        let decoded = hex::decode(&block.header.previous_hash)
            .context("failed to decode previous block hash")?;
        if decoded.len() != 32 {
            return Err(anyhow!(
                "expected previous block hash to decode to 32 bytes, got {}",
                decoded.len()
            ));
        }
        seed.copy_from_slice(&decoded);
    }

    let validators = membership
        .validators
        .iter()
        .map(|entry| ValidatorCandidate {
            address: entry.address.clone(),
            stake: entry.stake.clone(),
            reputation_score: entry.reputation_score,
            tier: entry.tier.clone(),
            timetoke_hours: entry.timetoke_hours,
        })
        .collect::<Vec<_>>();

    let observers = membership
        .observers
        .iter()
        .map(|entry| ObserverProfile {
            address: entry.address.clone(),
            tier: entry.tier.clone(),
        })
        .collect::<Vec<_>>();

    let mut vrf_keys: HashMap<String, VrfKeypair> = HashMap::new();
    for participant in participants {
        let keypair = load_keypair(&participant.config.key_path).with_context(|| {
            format!(
                "failed to load validator key material for node {}",
                participant.index
            )
        })?;
        let address = address_from_public_key(&keypair.public);
        let vrf_keypair =
            load_vrf_keypair(&participant.config.vrf_key_path).with_context(|| {
                format!(
                    "failed to load VRF key material for node {}",
                    participant.index
                )
            })?;
        vrf_keys.insert(address, vrf_keypair);
    }

    let round_number = block.consensus.round;
    let mut submissions = VrfSubmissionPool::new();
    for candidate in &validators {
        let vrf_keypair = vrf_keys.get(&candidate.address).with_context(|| {
            format!(
                "missing VRF keypair for validator {} while rebuilding submissions",
                candidate.address
            )
        })?;

        let tier_seed = derive_tier_seed(&candidate.address, candidate.timetoke_hours);
        let input = PoseidonVrfInput::new(seed, round_number, tier_seed);
        let proof = evaluate_vrf(
            &seed,
            round_number,
            &candidate.address,
            candidate.timetoke_hours,
            Some(&vrf_keypair.secret),
        )
        .with_context(|| {
            format!(
                "failed to evaluate VRF for validator {} in round {}",
                candidate.address, round_number
            )
        })?;

        submissions.insert(VrfSubmission {
            address: candidate.address.clone(),
            public_key: Some(vrf_keypair.public.clone()),
            input,
            proof,
            tier: candidate.tier.clone(),
            timetoke_hours: candidate.timetoke_hours,
        });
    }

    let mut round = ConsensusRound::new(
        block.header.height,
        round_number,
        seed,
        node.config.validator_set_size(),
        validators,
        observers,
        &submissions,
    );
    round.set_block_hash(block.hash.clone());
    Ok(round)
}

/// Generates prevote/precommit pairs for the supplied validators targeting the provided
/// consensus height, round and block hash.
pub fn signed_votes_for_round(
    validators: &[TestClusterNode],
    height: u64,
    round: u64,
    block_hash: &str,
) -> Result<Vec<(SignedBftVote, SignedBftVote)>> {
    let mut votes = Vec::with_capacity(validators.len());
    for node in validators {
        let keypair = load_keypair(&node.config.key_path).with_context(|| {
            format!(
                "failed to load validator key material for node {}",
                node.index
            )
        })?;
        let public_hex = hex::encode(keypair.public.to_bytes());
        let voter = address_from_public_key(&keypair.public);

        let prevote = BftVote {
            round,
            height,
            block_hash: block_hash.to_owned(),
            voter: voter.clone(),
            kind: BftVoteKind::PreVote,
        };
        let prevote_signature = sign_message(&keypair, &prevote.message_bytes());
        let signed_prevote = SignedBftVote {
            vote: prevote,
            public_key: public_hex.clone(),
            signature: signature_to_hex(&prevote_signature),
        };

        let precommit = BftVote {
            round,
            height,
            block_hash: block_hash.to_owned(),
            voter,
            kind: BftVoteKind::PreCommit,
        };
        let precommit_signature = sign_message(&keypair, &precommit.message_bytes());
        let signed_precommit = SignedBftVote {
            vote: precommit,
            public_key: public_hex,
            signature: signature_to_hex(&precommit_signature),
        };

        votes.push((signed_prevote, signed_precommit));
    }

    Ok(votes)
}
