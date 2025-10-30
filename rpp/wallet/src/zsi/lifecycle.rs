use std::fmt;

use crate::proof_backend::{
    Blake2sHasher, ProofBytes, ProofHeader, ProofSystemKind, ProvingKey, VerifyingKey,
    WitnessBytes, WitnessHeader,
};
use prover_backend_interface::{BackendError, BackendResult, IdentityPublicInputs, ProofBackend};
use serde::{Deserialize, Serialize};
use serde_json;

fn hash_bytes(input: &[u8]) -> [u8; 32] {
    Blake2sHasher::hash(input).into()
}

fn hash_hex(input: impl AsRef<[u8]>) -> String {
    hex::encode(hash_bytes(input.as_ref()))
}

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

impl ZsiRecord {
    fn new(identity: String, genesis_id: String, attestation_digest: String) -> Self {
        Self {
            identity,
            genesis_id,
            attestation_digest,
            approvals: Vec::new(),
        }
    }

    fn with_approvals(mut self, approvals: Vec<ConsensusApproval>) -> Self {
        self.approvals = approvals;
        self
    }
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

/// Compact representation of a lifecycle proof artefact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleProof {
    pub backend: String,
    pub operation: String,
    pub witness_digest: String,
    pub proof_commitment: String,
    pub raw_proof: Vec<u8>,
}

impl LifecycleProof {
    fn new(operation: &str, backend: &str, witness: &[u8], proof: &ProofBytes) -> Self {
        let witness_digest = hash_hex(witness);
        let proof_commitment = hash_hex(proof.as_slice());
        Self {
            backend: backend.to_string(),
            operation: operation.to_string(),
            witness_digest,
            proof_commitment,
            raw_proof: proof.clone().into_inner(),
        }
    }
}

/// High-level summary returned after a lifecycle operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiSummary {
    pub record: ZsiRecord,
    pub proof: Option<LifecycleProof>,
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
        proof: Option<LifecycleProof>,
    },
    Rotated {
        previous: ZsiRecord,
        updated: ZsiRecord,
        proof: Option<LifecycleProof>,
    },
    Revoked {
        identity: String,
        revocation_digest: String,
        proof: Option<LifecycleProof>,
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

fn approvals_digest(approvals: &[ConsensusApproval]) -> [u8; 32] {
    let encoded = serde_json::to_vec(approvals).unwrap_or_default();
    hash_bytes(&encoded)
}

fn identity_inputs(record: &ZsiRecord) -> IdentityPublicInputs {
    IdentityPublicInputs {
        wallet_address: hash_bytes(record.identity.as_bytes()),
        vrf_tag: record.attestation_digest.as_bytes().to_vec(),
        identity_root: hash_bytes(record.genesis_id.as_bytes()),
        state_root: approvals_digest(&record.approvals),
    }
}

fn operation_kind(name: &str) -> ProofSystemKind {
    match name {
        "stwo" => ProofSystemKind::Stwo,
        _ => ProofSystemKind::Mock,
    }
}

fn witness_header<'a>(backend: &'a dyn ProofBackend, operation: &str) -> WitnessHeader {
    WitnessHeader::new(
        operation_kind(backend.name()),
        format!("wallet.zsi.{operation}"),
    )
}

fn proof_header<'a>(backend: &'a dyn ProofBackend, operation: &str) -> ProofHeader {
    ProofHeader::new(
        operation_kind(backend.name()),
        format!("wallet.zsi.{operation}"),
    )
}

/// Lifecycle handler encapsulating the Zero Sync identity flows.
pub struct ZsiLifecycle<B> {
    backend: B,
}

impl<B> ZsiLifecycle<B>
where
    B: ProofBackend,
{
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn issue(&self, request: ZsiRequest) -> BackendResult<LifecycleReceipt> {
        let attestation_digest = hash_hex(request.attestation.as_bytes());
        let record = ZsiRecord::new(request.identity, request.genesis_id, attestation_digest)
            .with_approvals(request.approvals);
        let proof = self.prove("issue", &record)?;
        Ok(LifecycleReceipt::Issued { record, proof })
    }

    pub fn rotate(&self, request: RotateRequest) -> BackendResult<LifecycleReceipt> {
        let attestation = request
            .attestation
            .unwrap_or_else(|| request.previous.attestation_digest.clone());
        let attestation_digest = hash_hex(attestation.as_bytes());
        let updated = ZsiRecord::new(
            request.previous.identity.clone(),
            request.next_genesis_id,
            attestation_digest,
        )
        .with_approvals(request.approvals);
        let proof = self.prove("rotate", &updated)?;
        Ok(LifecycleReceipt::Rotated {
            previous: request.previous,
            updated,
            proof,
        })
    }

    pub fn revoke(&self, request: RevokeRequest) -> BackendResult<LifecycleReceipt> {
        let attestation = request
            .attestation
            .unwrap_or_else(|| request.reason.clone());
        let digest = hash_hex(attestation.as_bytes());
        let tombstone = ZsiRecord::new(request.identity.clone(), "revoked".into(), digest.clone());
        let proof = self.prove("revoke", &tombstone)?;
        Ok(LifecycleReceipt::Revoked {
            identity: request.identity,
            revocation_digest: digest,
            proof,
        })
    }

    pub fn audit(&self, record: ZsiRecord) -> BackendResult<LifecycleReceipt> {
        let proof = self.prove("audit", &record)?;
        let mut checks = Vec::new();
        if record.genesis_id.is_empty() {
            checks.push("genesis_id missing".into());
        }
        if record.attestation_digest.is_empty() {
            checks.push("attestation_digest missing".into());
        }
        if record.approvals.is_empty() {
            checks.push("no approvals attached".into());
        }
        if checks.is_empty() {
            checks.push("registry entry consistent".into());
        }
        let summary = ZsiSummary { record, proof };
        Ok(LifecycleReceipt::Audit(AuditReceipt { summary, checks }))
    }

    fn prove(&self, operation: &str, record: &ZsiRecord) -> BackendResult<Option<LifecycleProof>> {
        let header = witness_header(&self.backend, operation);
        let witness = WitnessBytes::encode(&header, record)?;
        let inputs = identity_inputs(record);
        match self
            .backend
            .prove_identity(&ProvingKey(Vec::new()), &witness)
        {
            Ok(proof) => {
                let header = proof_header(&self.backend, operation);
                let proof_bytes = ProofBytes::encode(&header, &proof)?;
                // Attempt verification; ignore unsupported backends.
                if let Err(err) =
                    self.backend
                        .verify_identity(&VerifyingKey(Vec::new()), &proof_bytes, &inputs)
                {
                    if !matches!(err, BackendError::Unsupported(_)) {
                        return Err(err);
                    }
                }
                Ok(Some(LifecycleProof::new(
                    operation,
                    self.backend.name(),
                    witness.as_slice(),
                    &proof_bytes,
                )))
            }
            Err(err) => match err {
                BackendError::Unsupported(_) => Ok(None),
                other => Err(other),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prover_backend_interface::BackendResult;
    use prover_mock_backend::MockBackend;

    fn sample_request() -> ZsiRequest {
        ZsiRequest {
            identity: "alice".into(),
            genesis_id: "genesis-1".into(),
            attestation: "proof".into(),
            approvals: vec![ConsensusApproval {
                validator: "validator-1".into(),
                signature: "cafebabe".into(),
                timestamp: 42,
            }],
        }
    }

    #[test]
    fn issue_records_digest() -> BackendResult<()> {
        let lifecycle = ZsiLifecycle::new(MockBackend::new());
        let receipt = lifecycle.issue(sample_request())?;
        match receipt {
            LifecycleReceipt::Issued { record, proof } => {
                assert_eq!(record.identity, "alice");
                assert!(record.attestation_digest.starts_with("c8"));
                assert!(proof.is_none());
            }
            _ => panic!("unexpected receipt variant"),
        }
        Ok(())
    }

    #[test]
    fn rotate_updates_genesis() -> BackendResult<()> {
        let lifecycle = ZsiLifecycle::new(MockBackend::new());
        let issued = match lifecycle.issue(sample_request())? {
            LifecycleReceipt::Issued { record, .. } => record,
            _ => unreachable!(),
        };
        let rotate = RotateRequest {
            previous: issued.clone(),
            next_genesis_id: "genesis-2".into(),
            attestation: Some("rotation".into()),
            approvals: issued.approvals.clone(),
        };
        let receipt = lifecycle.rotate(rotate)?;
        match receipt {
            LifecycleReceipt::Rotated { updated, .. } => {
                assert_eq!(updated.genesis_id, "genesis-2");
            }
            _ => panic!("unexpected variant"),
        }
        Ok(())
    }

    #[test]
    fn revoke_marks_identity() -> BackendResult<()> {
        let lifecycle = ZsiLifecycle::new(MockBackend::new());
        let receipt = lifecycle.revoke(RevokeRequest {
            identity: "alice".into(),
            reason: "compromised".into(),
            attestation: None,
        })?;
        match receipt {
            LifecycleReceipt::Revoked { identity, .. } => {
                assert_eq!(identity, "alice");
            }
            _ => panic!("unexpected variant"),
        }
        Ok(())
    }
}
