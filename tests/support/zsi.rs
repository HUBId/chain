use rpp_chain::types::AttestedIdentityRequest;
use serde_json::from_str;

const RENEWAL_FIXTURE_PATH: &str = "../vectors/zsi/renewal_request.json";

#[derive(Clone, Debug)]
pub struct AttestedIdentityRenewalFixture {
    pub request: AttestedIdentityRequest,
}

impl AttestedIdentityRenewalFixture {
    pub fn attestation_height(&self) -> u64 {
        self.request
            .attested_votes
            .first()
            .map(|vote| vote.vote.height)
            .expect("fixture attestation should include at least one vote")
    }
}

pub fn attested_identity_renewal_fixture() -> AttestedIdentityRenewalFixture {
    let request = from_str(include_str!(RENEWAL_FIXTURE_PATH))
        .expect("failed to parse attested identity request fixture");

    AttestedIdentityRenewalFixture { request }
}
