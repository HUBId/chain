use rpp_chain::types::AttestedIdentityRequest;
use serde_json::from_str;

pub fn attested_identity_renewal_fixture() -> AttestedIdentityRequest {
    from_str(include_str!("../vectors/zsi/renewal_request.json"))
        .expect("failed to parse attested identity request fixture")
}
