use rpp_chain::consensus::{
    classify_participants, evaluate_vrf, BftVote, BftVoteKind, ConsensusRound, SignedBftVote,
};
use rpp_chain::crypto::{
    address_from_public_key, generate_keypair, generate_vrf_keypair, sign_message, signature_to_hex,
};
use rpp_chain::reputation::Tier;
use rpp_chain::types::{Account, Stake};
use rpp_chain::vrf::{
    derive_tier_seed, PoseidonVrfInput, VrfProof, VrfSubmission, VrfSubmissionPool,
};

#[test]
fn consensus_ignores_duplicate_votes() {
    let keypair = generate_keypair();
    let address = address_from_public_key(&keypair.public);

    let mut account = Account::new(address.clone(), 1_000_000, Stake::from_u128(1_000));
    account.reputation.zsi.validate("genesis-proof");
    account.reputation.timetokes.hours_online = 48;
    account.reputation.consensus_success = 128;
    account.reputation.score = 1.0;
    account.reputation.promote_tier(Tier::Tl3);

    let (validators, observers) = classify_participants(&[account.clone()]);
    let mut submissions = VrfSubmissionPool::new();
    let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
    let tier_seed = derive_tier_seed(&account.address, account.reputation.timetokes.hours_online);
    let input = PoseidonVrfInput::new([0u8; 32], 1, tier_seed);
    let proof = evaluate_vrf(
        &[0u8; 32],
        1,
        &account.address,
        account.reputation.timetokes.hours_online,
        Some(&vrf_keypair.secret),
    )
    .expect("evaluate vrf");
    submissions.insert(VrfSubmission {
        address: account.address.clone(),
        public_key: Some(vrf_keypair.public.clone()),
        input: input.clone(),
        proof: VrfProof::from_output(&proof),
        tier: account.reputation.tier.clone(),
        timetoke_hours: account.reputation.timetokes.hours_online,
    });

    let mut round = ConsensusRound::new(1, 0, [0u8; 32], 1, validators, observers, &submissions);
    let block_hash = hex::encode([3u8; 32]);
    round.set_block_hash(block_hash.clone());

    let prevote = BftVote {
        round: round.round(),
        height: round.height(),
        block_hash: block_hash.clone(),
        voter: address.clone(),
        kind: BftVoteKind::PreVote,
    };
    let prevote_signature = sign_message(&keypair, &prevote.message_bytes());
    let signed_prevote = SignedBftVote {
        vote: prevote.clone(),
        public_key: hex::encode(keypair.public.to_bytes()),
        signature: signature_to_hex(&prevote_signature),
    };

    round
        .register_prevote(&signed_prevote)
        .expect("first prevote accepted");
    let certificate_before = round.certificate();
    assert_eq!(
        certificate_before.pre_votes.len(),
        1,
        "first prevote tracked once"
    );
    let prevote_power_before = certificate_before.pre_vote_power.clone();

    round
        .register_prevote(&signed_prevote)
        .expect("duplicate prevote ignored without error");
    let certificate_after = round.certificate();
    assert_eq!(
        certificate_after.pre_votes.len(),
        1,
        "duplicate prevote not duplicated"
    );
    assert_eq!(certificate_after.pre_vote_power, prevote_power_before);

    let precommit = BftVote {
        kind: BftVoteKind::PreCommit,
        ..prevote
    };
    let precommit_signature = sign_message(&keypair, &precommit.message_bytes());
    let signed_precommit = SignedBftVote {
        vote: precommit.clone(),
        public_key: hex::encode(keypair.public.to_bytes()),
        signature: signature_to_hex(&precommit_signature),
    };

    round
        .register_precommit(&signed_precommit)
        .expect("first precommit accepted");
    let commit_before = round.certificate();
    assert_eq!(
        commit_before.pre_commits.len(),
        1,
        "first precommit tracked once"
    );
    let precommit_power_before = commit_before.pre_commit_power.clone();

    round
        .register_precommit(&signed_precommit)
        .expect("duplicate precommit ignored");
    let commit_after = round.certificate();
    assert_eq!(
        commit_after.pre_commits.len(),
        1,
        "duplicate precommit not duplicated"
    );
    assert_eq!(commit_after.pre_commit_power, precommit_power_before);

    assert!(round.commit_reached(), "quorum satisfied");
    assert_eq!(round.commit_participants(), vec![address]);
}
