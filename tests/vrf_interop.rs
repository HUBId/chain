use rpp_chain::crypto::{VrfKeypair, generate_vrf_keypair, load_vrf_keypair, save_vrf_keypair};
use rpp_chain::reputation::Tier;
use rpp_chain::vrf::{
    PoseidonVrfInput, VrfProof, VrfSubmission, VrfSubmissionPool, generate_vrf, select_leader,
    select_validators, submit_vrf, verify_vrf,
};
use tempfile::tempdir;

fn sample_input() -> PoseidonVrfInput {
    PoseidonVrfInput::new([0xAA; 32], 17, [0x55; 32])
}

fn persist_and_reload(keypair: &VrfKeypair) -> VrfKeypair {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("vrf.toml");
    save_vrf_keypair(&path, keypair).expect("save vrf keypair");
    load_vrf_keypair(&path).expect("load vrf keypair")
}

#[test]
fn vrf_outputs_survive_disk_roundtrip_for_keys() {
    let keypair = generate_vrf_keypair().expect("generate vrf keypair");
    let reloaded = persist_and_reload(&keypair);

    let input = sample_input();
    let output = generate_vrf(&input, &reloaded.secret).expect("generate vrf");
    verify_vrf(&input, &reloaded.public, &output).expect("verify vrf");
}

#[test]
fn vrf_submission_roundtrip_after_reload() {
    let keypair = generate_vrf_keypair().expect("generate vrf keypair");
    let reloaded = persist_and_reload(&keypair);

    let input = sample_input();
    let output = generate_vrf(&input, &reloaded.secret).expect("generate vrf");
    let proof = VrfProof::from_output(&output);

    let mut pool = VrfSubmissionPool::new();
    let submission = VrfSubmission {
        address: "addr_vrf_roundtrip".to_string(),
        public_key: Some(reloaded.public.clone()),
        input: input.clone(),
        proof: proof.clone(),
        tier: Tier::Tl3,
        timetoke_hours: 24,
    };

    submit_vrf(&mut pool, submission);
    assert_eq!(pool.len(), 1);

    let selection = select_validators(&pool, 1);
    assert_eq!(selection.validators.len(), 1);
    assert!(selection.validators[0].verified);

    let leader = select_leader(&selection.validators).expect("leader");
    assert_eq!(leader.address, "addr_vrf_roundtrip");
}

#[test]
fn vrf_verification_rejects_tampered_proof() {
    let keypair = generate_vrf_keypair().expect("generate vrf keypair");
    let input = sample_input();
    let output = generate_vrf(&input, &keypair.secret).expect("generate vrf");

    let mut tampered = output.clone();
    tampered.proof[0] ^= 0x01;

    let error = verify_vrf(&input, &keypair.public, &tampered)
        .expect_err("tampered proof must fail verification");
    assert!(matches!(
        error,
        rpp_chain::vrf::VrfError::VerificationFailed | rpp_chain::vrf::VrfError::Backend(_)
    ));
}

#[test]
fn vrf_outputs_are_unpredictable_for_distinct_keys() {
    let input = sample_input();
    let first = generate_vrf_keypair().expect("generate vrf keypair");
    let second = generate_vrf_keypair().expect("generate vrf keypair");

    let first_output = generate_vrf(&input, &first.secret).expect("first vrf output");
    let second_output = generate_vrf(&input, &second.secret).expect("second vrf output");

    assert_ne!(first_output.randomness, second_output.randomness);
    assert_ne!(first_output.preoutput, second_output.preoutput);
}
