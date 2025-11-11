use hex::decode;
use rpp_chain::identity_tree::IdentityCommitmentTree;
use rpp_chain::ledger::{Ledger, SlashingReason, DEFAULT_EPOCH_LENGTH};
use rpp_chain::types::{
    Account, ChainProof, Stake, IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
};
mod support;

use support::{attested_identity_renewal_fixture, AttestedIdentityRenewalFixture};

#[test]
fn zsi_identity_submission_requires_bft_attestation() {
    let fixture = attested_identity_renewal_fixture();
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    assert_fixture_matches_pristine_ledger(&fixture, &ledger);
    let height = fixture.attestation_height();
    ledger.sync_epoch_for_height(height);

    let outcome = fixture
        .request
        .verify(
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("attestation should satisfy quorum");
    assert_eq!(
        outcome.approved_votes.len(),
        IDENTITY_ATTESTATION_QUORUM,
        "attestation quorum should persist after normalization",
    );
    assert!(
        outcome.slashable_validators.is_empty(),
        "fresh attestation should not flag slashable validators"
    );
    let _ = ledger.drain_module_witnesses();
    ledger
        .register_identity(
            &fixture.request,
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("ledger registers attested identity");
    let witnesses = ledger.drain_module_witnesses();
    let zsi_witness = witnesses
        .zsi
        .first()
        .expect("zsi witness emitted for identity registration");
    let recorded_validators: Vec<_> = zsi_witness
        .updated
        .approvals
        .iter()
        .map(|approval| approval.validator.clone())
        .collect();
    let expected_validators: Vec<_> = outcome
        .approved_votes
        .iter()
        .map(|vote| vote.vote.voter.clone())
        .collect();
    assert_eq!(
        recorded_validators, expected_validators,
        "witness should embed the attestation validators"
    );
    let expected_signatures: Vec<Vec<u8>> = outcome
        .approved_votes
        .iter()
        .map(|vote| decode(&vote.signature).expect("vote signature hex"))
        .collect();
    let recorded_signatures: Vec<&[u8]> = zsi_witness
        .updated
        .approvals
        .iter()
        .map(|approval| approval.signature.as_slice())
        .collect();
    assert_eq!(
        recorded_signatures,
        expected_signatures
            .iter()
            .map(|sig| sig.as_slice())
            .collect::<Vec<_>>(),
        "witness should persist the raw approval signatures",
    );
    assert!(
        zsi_witness
            .updated
            .approvals
            .iter()
            .all(|approval| approval.timestamp > 0),
        "approvals should capture issuance timestamps",
    );
    assert!(
        ledger.slashing_events(10).is_empty(),
        "valid attestation must not trigger slashing",
    );
}

#[test]
fn zsi_identity_submission_slashes_on_invalid_vote() {
    let fixture = attested_identity_renewal_fixture();
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    assert_fixture_matches_pristine_ledger(&fixture, &ledger);
    let height = fixture.attestation_height();
    ledger.sync_epoch_for_height(height);
    let mut invalid_request = fixture.request.clone();
    let mut faulty_vote = invalid_request
        .attested_votes
        .first()
        .expect("fixture includes at least one vote")
        .clone();
    faulty_vote.vote.height = height + 1;
    let faulty_validator = faulty_vote.vote.voter.clone();
    invalid_request.attested_votes.push(faulty_vote);

    let mut account = Account::new(faulty_validator.clone(), 0, Stake::default());
    account.reputation.zsi.public_key_commitment = IdentityCommitmentTree::default_leaf_hex();
    ledger
        .upsert_account(account)
        .expect("seed validator account for slashing checks");
    let _ = ledger.drain_module_witnesses();

    let outcome = invalid_request
        .verify(
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("attestation should retain quorum despite slashable vote");
    assert_eq!(
        outcome.slashable_validators.len(),
        1,
        "faulty vote should mark its validator as slashable",
    );
    ledger
        .register_identity(
            &invalid_request,
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("ledger should accept attestation after slashing offender");
    let slashes = ledger.slashing_events(10);
    assert_eq!(slashes.len(), 1, "slash log should record the offender");
    assert_eq!(
        slashes[0].address, outcome.slashable_validators[0],
        "slash event should identify the faulty validator",
    );
    assert_eq!(
        slashes[0].reason,
        SlashingReason::InvalidVote,
        "slash reason must denote invalid vote",
    );
    let witnesses = ledger.drain_module_witnesses();
    let zsi_witness = witnesses
        .zsi
        .iter()
        .find(|witness| witness.identity == invalid_request.declaration.genesis.wallet_addr)
        .expect("identity registration should emit witness");
    assert_eq!(
        zsi_witness.updated.approvals.len(),
        outcome.approved_votes.len(),
        "zsi witness should retain filtered approvals",
    );
}

fn assert_fixture_matches_pristine_ledger(
    fixture: &AttestedIdentityRenewalFixture,
    ledger: &Ledger,
) {
    let declaration = &fixture.request.declaration;
    let genesis = &declaration.genesis;

    assert_eq!(
        hex::encode(ledger.state_root()),
        genesis.state_root,
        "fresh ledger state root should match genesis snapshot"
    );
    assert_eq!(
        hex::encode(ledger.identity_root()),
        genesis.identity_root,
        "fresh ledger identity root should match genesis snapshot"
    );

    let expected_commitment = genesis
        .expected_commitment()
        .expect("genesis commitment should be derivable");
    assert_eq!(
        expected_commitment, declaration.proof.commitment,
        "expected Poseidon commitment must match declaration"
    );
    let ChainProof::Stwo(stark) = &declaration.proof.zk_proof else {
        panic!("identity fixture must include a STWO proof");
    };
    assert_eq!(
        expected_commitment, stark.commitment,
        "STWO proof commitment must match derived commitment"
    );

    let ledger_commitment_proof = ledger.identity_commitment_proof(&genesis.wallet_addr);
    assert_eq!(
        genesis.commitment_proof.leaf, ledger_commitment_proof.leaf,
        "fixture commitment leaf should match ledger snapshot"
    );
    assert_eq!(
        genesis.commitment_proof.siblings, ledger_commitment_proof.siblings,
        "fixture commitment proof path should match ledger snapshot"
    );
}
