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
