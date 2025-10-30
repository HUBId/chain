use prover_backend_interface::{BackendResult, ProofBackend};
use serde::{Deserialize, Serialize};

use crate::proof_backend::Blake2sHasher;
use crate::zsi::{
    ConsensusApproval, LifecycleReceipt, RevokeRequest as LifecycleRevoke,
    RotateRequest as LifecycleRotate, ZsiLifecycle, ZsiRecord, ZsiRequest,
};

fn digest(value: &str) -> String {
    let hash: [u8; 32] = Blake2sHasher::hash(value.as_bytes()).into();
    hex::encode(hash)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueParams {
    pub identity: String,
    pub genesis_id: String,
    pub attestation: String,
    #[serde(default)]
    pub approvals: Vec<ConsensusApproval>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateParams {
    pub identity: String,
    pub previous_genesis: String,
    pub previous_attestation: String,
    pub next_genesis: String,
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default)]
    pub approvals: Vec<ConsensusApproval>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeParams {
    pub identity: String,
    pub reason: String,
    #[serde(default)]
    pub attestation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditParams {
    pub identity: String,
    pub genesis_id: String,
    pub attestation: String,
    #[serde(default)]
    pub approvals: Vec<ConsensusApproval>,
}

pub fn issue<B: ProofBackend>(backend: B, params: IssueParams) -> BackendResult<LifecycleReceipt> {
    let lifecycle = ZsiLifecycle::new(backend);
    lifecycle.issue(ZsiRequest {
        identity: params.identity,
        genesis_id: params.genesis_id,
        attestation: params.attestation,
        approvals: params.approvals,
    })
}

pub fn rotate<B: ProofBackend>(
    backend: B,
    params: RotateParams,
) -> BackendResult<LifecycleReceipt> {
    let lifecycle = ZsiLifecycle::new(backend);
    let previous = ZsiRecord {
        identity: params.identity.clone(),
        genesis_id: params.previous_genesis,
        attestation_digest: digest(&params.previous_attestation),
        approvals: params.approvals.clone(),
    };
    lifecycle.rotate(LifecycleRotate {
        previous,
        next_genesis_id: params.next_genesis,
        attestation: params.attestation,
        approvals: params.approvals,
    })
}

pub fn revoke<B: ProofBackend>(
    backend: B,
    params: RevokeParams,
) -> BackendResult<LifecycleReceipt> {
    let lifecycle = ZsiLifecycle::new(backend);
    lifecycle.revoke(LifecycleRevoke {
        identity: params.identity,
        reason: params.reason,
        attestation: params.attestation,
    })
}

pub fn audit<B: ProofBackend>(backend: B, params: AuditParams) -> BackendResult<LifecycleReceipt> {
    let lifecycle = ZsiLifecycle::new(backend);
    let record = ZsiRecord {
        identity: params.identity,
        genesis_id: params.genesis_id,
        attestation_digest: digest(&params.attestation),
        approvals: params.approvals,
    };
    lifecycle.audit(record)
}
