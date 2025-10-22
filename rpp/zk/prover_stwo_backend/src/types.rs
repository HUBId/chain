use std::convert::TryInto;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::errors::{ChainError, ChainResult};
use crate::proof_backend::{Blake2sHasher, ProofSystemKind};
use crate::reputation::ReputationProfile;

/// Light-weight stake representation used throughout the blueprint circuits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stake {
    pub bonded: u128,
}

impl Stake {
    pub fn new(bonded: u128) -> Self {
        Self { bonded }
    }
}

impl Default for Stake {
    fn default() -> Self {
        Self { bonded: 0 }
    }
}

/// Minimal account representation sufficient for circuit replays.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
    pub stake: Stake,
    #[serde(default)]
    pub reputation: ReputationProfile,
}

impl Account {
    pub fn new(address: String, balance: u128, stake: Stake) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
            stake,
            reputation: ReputationProfile::default(),
        }
    }

    pub fn ensure_wallet_binding(&mut self, wallet_pk_hex: &str) -> Result<(), AccountError> {
        let public_key = hex::decode(wallet_pk_hex)
            .map_err(|err| AccountError::InvalidWalletKey(err.to_string()))?;
        let commitment: [u8; 32] = Blake2sHasher::hash(&public_key).into();
        let derived_address = hex::encode(commitment);
        if derived_address != self.address {
            return Err(AccountError::WalletAddressMismatch);
        }
        self.reputation.wallet_commitment = Some(derived_address);
        Ok(())
    }
}

/// Errors raised when validating account bindings.
#[derive(Debug, Error)]
pub enum AccountError {
    #[error("invalid wallet public key: {0}")]
    InvalidWalletKey(String),
    #[error("wallet public key does not match account address")]
    WalletAddressMismatch,
}

/// Blueprint transaction payload mirroring the runtime structure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: u128,
    pub fee: u64,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    pub timestamp: u64,
}

impl Transaction {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("transaction serialization never fails")
    }
}

/// Signed transaction wrapper storing the verifying key alongside the payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTransaction {
    pub payload: Transaction,
    pub signature: String,
    pub public_key: String,
}

impl SignedTransaction {
    pub fn new(payload: Transaction, signature: Signature, public_key: &VerifyingKey) -> Self {
        Self {
            payload,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(public_key.to_bytes()),
        }
    }

    pub fn verify(&self) -> Result<(), SignedTransactionError> {
        let pk_bytes = hex::decode(&self.public_key)
            .map_err(|err| SignedTransactionError::InvalidPublicKey(err.to_string()))?;
        let pk_array: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
            SignedTransactionError::InvalidPublicKey(
                "ed25519 public key must encode 32 bytes".into(),
            )
        })?;
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|err| SignedTransactionError::InvalidSignature(err.to_string()))?;
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            SignedTransactionError::InvalidSignature(
                "ed25519 signature must encode 64 bytes".into(),
            )
        })?;
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|err| SignedTransactionError::InvalidPublicKey(err.to_string()))?;
        let signature = Signature::from_bytes(&sig_array);
        verifying_key
            .verify(&self.payload.canonical_bytes(), &signature)
            .map_err(|_| SignedTransactionError::VerificationFailed)
    }
}

/// Errors emitted by the signed transaction helpers.
#[derive(Debug, Error)]
pub enum SignedTransactionError {
    #[error("invalid public key encoding: {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),
    #[error("transaction signature verification failed")]
    VerificationFailed,
}

/// Identity declaration embedded in attested identity requests.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityDeclaration {
    pub genesis: IdentityGenesis,
    pub proof: IdentityProof,
}

/// Genesis data for an identity request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityGenesis {
    pub wallet_addr: String,
    pub wallet_pk: String,
}

/// Proof metadata associated with an identity declaration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityProof {
    pub commitment: String,
}

/// Request submitted to include a new identity in the state tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestedIdentityRequest {
    pub declaration: IdentityDeclaration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,
}

impl AttestedIdentityRequest {
    pub fn new(declaration: IdentityDeclaration) -> Self {
        Self {
            declaration,
            attester: None,
        }
    }
}

/// Static helpers for uptime proofs referenced by the circuits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UptimeProof;

impl UptimeProof {
    pub fn commitment_bytes(address: &str, window_start: u64, window_end: u64) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(address.as_bytes());
        data.extend_from_slice(&window_start.to_be_bytes());
        data.extend_from_slice(&window_end.to_be_bytes());
        Blake2sHasher::hash(&data).into()
    }
}

/// Blueprint wrapper around the STWO proof artifacts used throughout the
/// verifier.  The enum keeps the shape of the production type but limits the
/// variants to what the local backend exposes.
#[cfg(feature = "official")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChainProof {
    #[serde(rename = "stwo")]
    Stwo(crate::official::proof::StarkProof),
    #[serde(other)]
    Other,
}

#[cfg(not(feature = "official"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChainProof {
    #[serde(other)]
    Other,
}

impl ChainProof {
    pub fn system(&self) -> ProofSystemKind {
        match self {
            #[cfg(feature = "official")]
            ChainProof::Stwo(_) => ProofSystemKind::Stwo,
            _ => ProofSystemKind::Mock,
        }
    }

    #[cfg(feature = "official")]
    pub fn expect_stwo(&self) -> ChainResult<&crate::official::proof::StarkProof> {
        match self {
            ChainProof::Stwo(proof) => Ok(proof),
            ChainProof::Other => Err(ChainError::Crypto(
                "expected STWO proof, received unsupported artifact".into(),
            )),
        }
    }

    #[cfg(feature = "official")]
    pub fn into_stwo(self) -> ChainResult<crate::official::proof::StarkProof> {
        match self {
            ChainProof::Stwo(proof) => Ok(proof),
            ChainProof::Other => Err(ChainError::Crypto(
                "expected STWO proof, received unsupported artifact".into(),
            )),
        }
    }
}
