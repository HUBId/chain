use rpp_chain::runtime::vrf_gossip::{
    gossip_to_submission, submission_to_gossip, verify_submission,
};
use rpp_chain::vrf::{
    generate_vrf, generate_vrf_keypair, PoseidonVrfInput, Tier, VrfProof, VrfSubmission,
};

fn sample_submission() -> VrfSubmission {
    let keypair = generate_vrf_keypair();
    let input = PoseidonVrfInput::new([0x11; 32], 42, [0x22; 32]);
    let output = generate_vrf(&input, &keypair.secret).expect("generate vrf output");
    VrfSubmission {
        address: "validator-01".to_string(),
        public_key: Some(keypair.public.clone()),
        input,
        proof: VrfProof::from_output(&output),
        tier: Tier::Tl3,
        timetoke_hours: 128,
    }
}

#[test]
fn vrf_gossip_payload_roundtrip() {
    let submission = sample_submission();
    verify_submission(&submission).expect("submission must verify");

    let payload = submission_to_gossip(&submission);
    let encoded = serde_json::to_vec(&payload).expect("encode gossip payload");
    let decoded_payload = serde_json::from_slice(&encoded).expect("decode gossip payload");
    let reconstructed = gossip_to_submission(decoded_payload).expect("payload to submission");

    assert_eq!(reconstructed.address, submission.address);
    assert_eq!(reconstructed.input, submission.input);
    assert_eq!(reconstructed.proof, submission.proof);
    assert_eq!(reconstructed.tier, submission.tier);
    assert_eq!(reconstructed.timetoke_hours, submission.timetoke_hours);
    assert!(reconstructed.public_key.is_some());
    verify_submission(&reconstructed).expect("roundtrip submission must verify");
}

#[test]
fn vrf_gossip_rejects_modified_proof() {
    let mut submission = sample_submission();
    submission.proof.randomness += 1u32.into();
    let err = verify_submission(&submission).expect_err("verification must fail");
    assert!(err.to_string().contains("verification failed"));
}
