use hex::FromHex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::errors::ChainError;
use crate::types::Address;
use crate::vrf::{
    self, vrf_public_key_from_hex, vrf_public_key_to_hex, PoseidonVrfInput, VrfProof, VrfSubmission,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipVrfSubmission {
    pub address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub input: GossipVrfInput,
    pub proof: VrfProof,
    pub tier: crate::vrf::Tier,
    pub timetoke_hours: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipVrfInput {
    pub last_block_header: String,
    pub epoch: u64,
    pub tier_seed: String,
}

#[derive(Debug, Error)]
pub enum GossipVrfError {
    #[error("vrf gossip missing public key")]
    MissingPublicKey,
    #[error("invalid vrf gossip hex encoding for {field}: {reason}")]
    InvalidHex { field: &'static str, reason: String },
    #[error("invalid vrf gossip length for {field}")]
    InvalidLength { field: &'static str },
    #[error("invalid vrf gossip proof: {0}")]
    InvalidProof(String),
    #[error("vrf proof verification failed: {0}")]
    VerificationFailed(String),
}

impl From<GossipVrfError> for ChainError {
    fn from(err: GossipVrfError) -> Self {
        ChainError::Crypto(err.to_string())
    }
}

impl GossipVrfSubmission {
    pub fn from_submission(submission: &VrfSubmission) -> Self {
        let public_key = submission.public_key.as_ref().map(vrf_public_key_to_hex);
        Self {
            address: submission.address.clone(),
            public_key,
            input: GossipVrfInput {
                last_block_header: hex::encode(submission.input.last_block_header),
                epoch: submission.input.epoch,
                tier_seed: hex::encode(submission.input.tier_seed),
            },
            proof: submission.proof.clone(),
            tier: submission.tier.clone(),
            timetoke_hours: submission.timetoke_hours,
        }
    }

    pub fn into_submission(self) -> Result<VrfSubmission, GossipVrfError> {
        let last_block_header =
            decode_hex_array(&self.input.last_block_header, "last_block_header")?;
        let tier_seed = decode_hex_array(&self.input.tier_seed, "tier_seed")?;
        let input = PoseidonVrfInput::new(last_block_header, self.input.epoch, tier_seed);
        let public_key =
            match self.public_key {
                Some(hex) => Some(vrf_public_key_from_hex(&hex).map_err(|err| {
                    GossipVrfError::InvalidHex {
                        field: "public_key",
                        reason: err.to_string(),
                    }
                })?),
                None => None,
            };
        Ok(VrfSubmission {
            address: self.address,
            public_key,
            input,
            proof: self.proof,
            tier: self.tier,
            timetoke_hours: self.timetoke_hours,
        })
    }
}

pub fn verify_submission(submission: &VrfSubmission) -> Result<(), GossipVrfError> {
    let public_key = submission
        .public_key
        .as_ref()
        .ok_or(GossipVrfError::MissingPublicKey)?;
    let output = submission
        .proof
        .to_vrf_output()
        .map_err(|err| GossipVrfError::InvalidProof(err.to_string()))?;
    vrf::verify_vrf(&submission.input, public_key, &output)
        .map_err(|err| GossipVrfError::VerificationFailed(err.to_string()))
}

pub fn submission_to_gossip(submission: &VrfSubmission) -> GossipVrfSubmission {
    GossipVrfSubmission::from_submission(submission)
}

pub fn gossip_to_submission(payload: GossipVrfSubmission) -> Result<VrfSubmission, GossipVrfError> {
    payload.into_submission()
}

fn decode_hex_array<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], GossipVrfError> {
    let bytes = Vec::from_hex(value).map_err(|err| GossipVrfError::InvalidHex {
        field,
        reason: err.to_string(),
    })?;
    let array: [u8; N] = bytes
        .try_into()
        .map_err(|_| GossipVrfError::InvalidLength { field })?;
    Ok(array)
}
