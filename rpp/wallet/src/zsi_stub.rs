#![allow(dead_code)]

//! Zero Sync identity stubs compiled when the `wallet_zsi` feature is disabled.
//!
//! The wallet expects these types to exist even when Zero Sync workflows are
//! turned off. All runtime operations return a [`BackendError::Unsupported`]
//! with a message indicating that the feature has been disabled.

use prover_backend_interface::{BackendError, BackendResult, ProofBackend};

const FEATURE_DISABLED: &str = "wallet_zsi feature disabled";

fn feature_disabled<T>() -> BackendResult<T> {
    Err(BackendError::Unsupported(FEATURE_DISABLED))
}

/// Stubbed bind helpers.
pub mod bind {
    use super::{feature_disabled, BackendResult, ProofBackend};
    use crate::proof_backend::{ProofBytes, WitnessBytes};
    use serde::{Deserialize, Serialize};
    use std::fmt;

    /// Operations supported by the Zero Sync identity prover.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub enum ZsiOperation {
        Issue,
        Rotate,
        Revoke,
        Audit,
    }

    impl ZsiOperation {
        /// Return the canonical operation label expected by the prover backend.
        pub fn as_str(&self) -> &'static str {
            match self {
                ZsiOperation::Issue => "issue",
                ZsiOperation::Rotate => "rotate",
                ZsiOperation::Revoke => "revoke",
                ZsiOperation::Audit => "audit",
            }
        }
    }

    impl AsRef<str> for ZsiOperation {
        fn as_ref(&self) -> &str {
            self.as_str()
        }
    }

    impl fmt::Display for ZsiOperation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.as_str())
        }
    }

    /// Helper that mirrors the binder API but reports the disabled feature.
    #[derive(Clone, Debug)]
    pub struct ZsiBinder {
        operation: ZsiOperation,
    }

    impl ZsiBinder {
        /// Construct a binder for the given backend and lifecycle operation.
        ///
        /// This stub ignores the backend and always reports that the feature is
        /// disabled when encoding witnesses or proofs.
        pub fn new<B: ProofBackend>(_backend: &B, operation: ZsiOperation) -> Self {
            Self { operation }
        }

        /// Lifecycle operation attached to this binder.
        pub fn operation(&self) -> ZsiOperation {
            self.operation
        }

        /// Encode a witness payload using the lifecycle headers.
        ///
        /// The stub always returns a feature-disabled error.
        pub fn encode_witness<T: Serialize>(&self, _payload: &T) -> BackendResult<WitnessBytes> {
            feature_disabled()
        }

        /// Encode a proof payload using the lifecycle headers.
        ///
        /// The stub always returns a feature-disabled error.
        pub fn encode_proof<T: Serialize>(&self, _payload: &T) -> BackendResult<ProofBytes> {
            feature_disabled()
        }
    }
}

/// Stubbed lifecycle workflows.
pub mod lifecycle {
    use super::{feature_disabled, BackendResult, ProofBackend};
    use serde::{Deserialize, Serialize};
    use std::fmt;

    /// Approval emitted by consensus while onboarding an identity.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct ConsensusApproval {
        pub validator: String,
        pub signature: String,
        pub timestamp: u64,
    }

    /// Canonical ZSI registry record summarising a wallet identity.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ZsiRecord {
        pub identity: String,
        pub genesis_id: String,
        pub attestation_digest: String,
        pub approvals: Vec<ConsensusApproval>,
    }

    /// Payload required when issuing a new ZSI identity.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ZsiRequest {
        pub identity: String,
        pub genesis_id: String,
        pub attestation: String,
        #[serde(default)]
        pub approvals: Vec<ConsensusApproval>,
    }

    /// Payload used when rotating an existing identity to a new commitment.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RotateRequest {
        pub previous: ZsiRecord,
        pub next_genesis_id: String,
        #[serde(default)]
        pub attestation: Option<String>,
        #[serde(default)]
        pub approvals: Vec<ConsensusApproval>,
    }

    /// Payload used when revoking a compromised identity.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RevokeRequest {
        pub identity: String,
        pub reason: String,
        #[serde(default)]
        pub attestation: Option<String>,
    }

    /// High-level summary returned after a lifecycle operation.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ZsiSummary {
        pub record: ZsiRecord,
        pub proof: Option<super::super::prove::LifecycleProof>,
    }

    /// Result of auditing the current identity state.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AuditReceipt {
        pub summary: ZsiSummary,
        pub checks: Vec<String>,
    }

    /// Receipt returned by lifecycle operations.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "operation", rename_all = "snake_case")]
    pub enum LifecycleReceipt {
        Issued {
            record: ZsiRecord,
            proof: Option<super::super::prove::LifecycleProof>,
        },
        Rotated {
            previous: ZsiRecord,
            updated: ZsiRecord,
            proof: Option<super::super::prove::LifecycleProof>,
        },
        Revoked {
            identity: String,
            revocation_digest: String,
            proof: Option<super::super::prove::LifecycleProof>,
        },
        Audit(AuditReceipt),
    }

    impl fmt::Display for LifecycleReceipt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                LifecycleReceipt::Issued { record, .. } => {
                    write!(f, "issued identity {}", record.identity)
                }
                LifecycleReceipt::Rotated { updated, .. } => {
                    write!(f, "rotated identity {}", updated.identity)
                }
                LifecycleReceipt::Revoked { identity, .. } => {
                    write!(f, "revoked identity {identity}")
                }
                LifecycleReceipt::Audit(receipt) => {
                    write!(f, "audit identity {}", receipt.summary.record.identity)
                }
            }
        }
    }

    /// Lifecycle handler encapsulating the Zero Sync identity flows.
    #[derive(Clone, Debug)]
    pub struct ZsiLifecycle<B> {
        backend: B,
    }

    impl<B> ZsiLifecycle<B> {
        /// Construct a lifecycle handler backed by the provided prover backend.
        pub fn new(backend: B) -> Self {
            Self { backend }
        }
    }

    impl<B> ZsiLifecycle<B>
    where
        B: ProofBackend,
    {
        /// Issue a new ZSI identity.
        ///
        /// The stub always returns a feature-disabled error.
        pub fn issue(&self, _request: ZsiRequest) -> BackendResult<LifecycleReceipt> {
            let _ = &self.backend;
            feature_disabled()
        }

        /// Rotate an existing identity to a new genesis commitment.
        ///
        /// The stub always returns a feature-disabled error.
        pub fn rotate(&self, _request: RotateRequest) -> BackendResult<LifecycleReceipt> {
            let _ = &self.backend;
            feature_disabled()
        }

        /// Revoke an existing identity.
        ///
        /// The stub always returns a feature-disabled error.
        pub fn revoke(&self, _request: RevokeRequest) -> BackendResult<LifecycleReceipt> {
            let _ = &self.backend;
            feature_disabled()
        }

        /// Audit a registry record.
        ///
        /// The stub always returns a feature-disabled error.
        pub fn audit(&self, _record: ZsiRecord) -> BackendResult<LifecycleReceipt> {
            let _ = &self.backend;
            feature_disabled()
        }
    }

    /// Helper retained for API parity; always returns an empty list.
    pub fn approvals_digest(_approvals: &[ConsensusApproval]) -> [u8; 32] {
        [0u8; 32]
    }

    /// Helper retained for API parity; always returns zeroed inputs.
    pub fn identity_inputs(_record: &ZsiRecord) -> crate::proof_backend::IdentityPublicInputs {
        crate::proof_backend::IdentityPublicInputs {
            wallet_address: [0u8; 32],
            vrf_tag: Vec::new(),
            identity_root: [0u8; 32],
            state_root: [0u8; 32],
        }
    }
}

/// Stubbed proving helpers.
pub mod prove {
    use super::{feature_disabled, BackendResult, ProofBackend};
    use crate::proof_backend::{Blake2sHasher, IdentityPublicInputs, ProofBytes, WitnessBytes};
    use serde::{Deserialize, Serialize};

    use super::super::bind::ZsiBinder;

    /// Compact representation of a lifecycle proof artefact.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct LifecycleProof {
        pub backend: String,
        pub operation: String,
        pub witness_digest: String,
        pub proof_commitment: String,
        pub raw_proof: Vec<u8>,
    }

    pub(crate) fn hash_bytes(input: &[u8]) -> [u8; 32] {
        Blake2sHasher::hash(input).into()
    }

    pub fn hash_hex(input: impl AsRef<[u8]>) -> String {
        hex::encode(hash_bytes(input.as_ref()))
    }

    /// Generate a lifecycle proof for the provided witness and inputs.
    ///
    /// The stub always returns a feature-disabled error.
    pub fn generate<B: ProofBackend>(
        backend: &B,
        binder: &ZsiBinder,
        witness: WitnessBytes,
        inputs: IdentityPublicInputs,
    ) -> BackendResult<Option<LifecycleProof>> {
        let _ = backend;
        let _ = binder;
        let _ = witness;
        let _ = inputs;
        feature_disabled()
    }
}

/// Stubbed verification helpers.
pub mod verify {
    use super::{feature_disabled, BackendResult, ProofBackend};
    use crate::proof_backend::{IdentityPublicInputs, ProofBytes};

    /// Verify a lifecycle proof for the provided inputs.
    ///
    /// The stub always returns a feature-disabled error.
    pub fn identity<B: ProofBackend>(
        backend: &B,
        proof: &ProofBytes,
        inputs: &IdentityPublicInputs,
    ) -> BackendResult<()> {
        let _ = backend;
        let _ = proof;
        let _ = inputs;
        feature_disabled()
    }
}

pub use bind::{ZsiBinder, ZsiOperation};
pub use lifecycle::{
    AuditReceipt, ConsensusApproval, LifecycleReceipt, RevokeRequest, RotateRequest, ZsiLifecycle,
    ZsiRecord, ZsiRequest, ZsiSummary,
};
pub use prove::LifecycleProof;
