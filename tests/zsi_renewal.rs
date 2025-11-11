use rpp_chain::ledger::{Ledger, DEFAULT_EPOCH_LENGTH};
use rpp_chain::types::{
    IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
};
mod support;

use support::attested_identity_renewal_fixture;

#[test]
#[ignore]
fn zsi_identity_submission_requires_bft_attestation() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    let fixture = attested_identity_renewal_fixture();
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
#[ignore]
fn zsi_identity_submission_slashes_on_invalid_vote() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    let fixture = attested_identity_renewal_fixture();
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
