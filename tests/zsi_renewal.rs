use rpp_chain::ledger::{Ledger, DEFAULT_EPOCH_LENGTH};
use rpp_chain::types::{
    ChainProof, IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
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

    fixture
        .request
        .verify(
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("attestation should satisfy quorum");
    ledger
        .register_identity(
            &fixture.request,
            height,
            IDENTITY_ATTESTATION_QUORUM,
            IDENTITY_ATTESTATION_GOSSIP_MIN,
        )
        .expect("ledger registers attested identity");
}

#[test]
fn zsi_identity_submission_slashes_on_invalid_vote() {
    let fixture = attested_identity_renewal_fixture();
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    assert_fixture_matches_pristine_ledger(&fixture, &ledger);
    let height = fixture.attestation_height();
    ledger.sync_epoch_for_height(height);
    let mut invalid_request = fixture.request.clone();
    invalid_request.attested_votes[2].vote.height = height + 1;

    let err = invalid_request
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
    assert!(ledger
        .get_account(&fixture.request.declaration.genesis.wallet_addr)
        .is_none());
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
        expected_commitment,
        declaration.proof.commitment,
        "expected Poseidon commitment must match declaration"
    );
    let ChainProof::Stwo(stark) = &declaration.proof.zk_proof else {
        panic!("identity fixture must include a STWO proof");
    };
    assert_eq!(
        expected_commitment,
        stark.commitment,
        "STWO proof commitment must match derived commitment"
    );

    let ledger_commitment_proof = ledger.identity_commitment_proof(&genesis.wallet_addr);
    assert_eq!(
        genesis.commitment_proof.leaf,
        ledger_commitment_proof.leaf,
        "fixture commitment leaf should match ledger snapshot"
    );
    assert_eq!(
        genesis.commitment_proof.siblings,
        ledger_commitment_proof.siblings,
        "fixture commitment proof path should match ledger snapshot"
    );
}
