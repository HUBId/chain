use insta::assert_json_snapshot;
use proptest::prelude::*;
use rpp_stark::params::{BuiltinProfile, StarkParamsBuilder};
use rpp_stark::transcript::{Transcript, TranscriptContext, TranscriptError, TranscriptLabel};
use rpp_stark::utils::serialization::DigestBytes;

fn sample_params(profile: BuiltinProfile) -> rpp_stark::params::StarkParams {
    StarkParamsBuilder::from_profile(profile)
        .build()
        .expect("profile must be valid")
}

fn sample_digest(byte: u8) -> DigestBytes {
    DigestBytes { bytes: [byte; 32] }
}

#[test]
fn deterministic_state_digest() {
    let params = sample_params(BuiltinProfile::PROFILE_X8);
    let mut t1 = Transcript::new(&params, TranscriptContext::StarkMain);
    let mut t2 = Transcript::new(&params, TranscriptContext::StarkMain);

    let public = sample_digest(1);
    t1.absorb_digest(TranscriptLabel::PublicInputsDigest, &public)
        .unwrap();
    t2.absorb_digest(TranscriptLabel::PublicInputsDigest, &public)
        .unwrap();

    let trace_root = sample_digest(2);
    t1.absorb_digest(TranscriptLabel::TraceRoot, &trace_root)
        .unwrap();
    t2.absorb_digest(TranscriptLabel::TraceRoot, &trace_root)
        .unwrap();

    let trace_challenge_a1 = t1
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .unwrap();
    let trace_challenge_a2 = t2
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .unwrap();
    assert_eq!(trace_challenge_a1, trace_challenge_a2);

    let comp_root = sample_digest(3);
    t1.absorb_digest(TranscriptLabel::CompRoot, &comp_root)
        .unwrap();
    t2.absorb_digest(TranscriptLabel::CompRoot, &comp_root)
        .unwrap();

    let comp_challenge_a1 = t1.challenge_field(TranscriptLabel::CompChallengeA).unwrap();
    let comp_challenge_a2 = t2.challenge_field(TranscriptLabel::CompChallengeA).unwrap();
    assert_eq!(comp_challenge_a1, comp_challenge_a2);

    let mut fri_folds = Vec::new();
    for layer in 0..params.fri().num_layers {
        let fri_root = sample_digest(10 + layer);
        t1.absorb_digest(TranscriptLabel::FriRoot(layer), &fri_root)
            .unwrap();
        t2.absorb_digest(TranscriptLabel::FriRoot(layer), &fri_root)
            .unwrap();
        let fold_a1 = t1
            .challenge_field(TranscriptLabel::FriFoldChallenge(layer))
            .unwrap();
        let fold_a2 = t2
            .challenge_field(TranscriptLabel::FriFoldChallenge(layer))
            .unwrap();
        assert_eq!(fold_a1, fold_a2);
        fri_folds.push(fold_a1);
        // absorb the same digest after comparing to maintain ordering
    }

    let queries = params.fri().queries.to_le_bytes();
    t1.absorb_bytes(TranscriptLabel::QueryCount, &queries)
        .unwrap();
    t2.absorb_bytes(TranscriptLabel::QueryCount, &queries)
        .unwrap();

    let domain_size = 1usize << params.fri().domain_log2;
    let sample_count = 4usize;
    let mut idxs1 = Vec::new();
    let mut idxs2 = Vec::new();
    for _ in 0..sample_count {
        idxs1.push(
            t1.challenge_usize(TranscriptLabel::QueryIndexStream, domain_size)
                .unwrap(),
        );
        idxs2.push(
            t2.challenge_usize(TranscriptLabel::QueryIndexStream, domain_size)
                .unwrap(),
        );
    }
    assert_eq!(idxs1, idxs2);

    let close1 = t1.challenge_bytes(TranscriptLabel::ProofClose, 32).unwrap();
    let close2 = t2.challenge_bytes(TranscriptLabel::ProofClose, 32).unwrap();
    assert_eq!(close1, close2);
    let proof_close_hex: String = close1.iter().map(|b| format!("{:02x}", b)).collect();
    let fri_fold_scalars: Vec<u64> = fri_folds
        .iter()
        .map(|f| u64::try_from(*f).expect("canonical fold scalar"))
        .collect();
    assert_json_snapshot!(
        "transcript_profile_x8",
        serde_json::json!({
            "trace_challenge": u64::try_from(trace_challenge_a1)
                .expect("canonical trace challenge"),
            "comp_challenge": u64::try_from(comp_challenge_a1)
                .expect("canonical composition challenge"),
            "fri_folds": fri_fold_scalars,
            "query_indices": idxs1,
            "proof_close_hex": proof_close_hex,
        })
    );
    assert_eq!(t1.state_digest(), t2.state_digest());
}

#[test]
fn different_order_changes_digest() {
    let params = sample_params(BuiltinProfile::PROFILE_X8);
    let mut ordered = Transcript::new(&params, TranscriptContext::StarkMain);
    let mut shuffled = Transcript::new(&params, TranscriptContext::StarkMain);

    let public = sample_digest(4);
    ordered
        .absorb_digest(TranscriptLabel::PublicInputsDigest, &public)
        .unwrap();
    shuffled
        .absorb_digest(TranscriptLabel::PublicInputsDigest, &public)
        .unwrap();

    let trace_root = sample_digest(5);
    ordered
        .absorb_digest(TranscriptLabel::TraceRoot, &trace_root)
        .unwrap();
    shuffled
        .absorb_digest(TranscriptLabel::TraceRoot, &trace_root)
        .unwrap();

    let _ = ordered
        .challenge_field(TranscriptLabel::TraceChallengeA)
        .unwrap();
    let comp_root = sample_digest(6);
    ordered
        .absorb_digest(TranscriptLabel::CompRoot, &comp_root)
        .unwrap();
    let _ = ordered
        .challenge_field(TranscriptLabel::CompChallengeA)
        .unwrap();

    // Shuffled variant skips comp root before taking challenge which must fail.
    let err = shuffled
        .challenge_field(TranscriptLabel::CompChallengeA)
        .unwrap_err();
    assert_eq!(err, TranscriptError::InvalidLabel);
}

proptest! {
    #[test]
    fn usize_challenges_respect_range(range in 1usize..1024usize) {
        let params = sample_params(BuiltinProfile::PROFILE_X8);
        let mut transcript = Transcript::new(&params, TranscriptContext::StarkMain);
        let public = sample_digest(7);
        transcript.absorb_digest(TranscriptLabel::PublicInputsDigest, &public).unwrap();
        let trace = sample_digest(8);
        transcript.absorb_digest(TranscriptLabel::TraceRoot, &trace).unwrap();
        let _ = transcript.challenge_field(TranscriptLabel::TraceChallengeA).unwrap();
        let comp = sample_digest(9);
        transcript.absorb_digest(TranscriptLabel::CompRoot, &comp).unwrap();
        let _ = transcript.challenge_field(TranscriptLabel::CompChallengeA).unwrap();
        for layer in 0..params.fri().num_layers {
            let fri_root = sample_digest(20 + layer);
            transcript
                .absorb_digest(TranscriptLabel::FriRoot(layer), &fri_root)
                .unwrap();
            let _ = transcript
                .challenge_field(TranscriptLabel::FriFoldChallenge(layer))
                .unwrap();
        }
        transcript
            .absorb_bytes(TranscriptLabel::QueryCount, &params.fri().queries.to_le_bytes())
            .unwrap();
        let idx = transcript.challenge_usize(TranscriptLabel::QueryIndexStream, range).unwrap();
        prop_assert!(idx < range);
    }
}
