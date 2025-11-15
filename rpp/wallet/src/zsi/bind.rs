use crate::proof_backend::{ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes, WitnessHeader};
use prover_backend_interface::{BackendResult, ProofBackend};
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

    fn circuit(&self) -> String {
        format!("wallet.zsi.{}", self.as_str())
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

fn system_kind(name: &str) -> ProofSystemKind {
    match name {
        "stwo" => ProofSystemKind::Stwo,
        _ => ProofSystemKind::Mock,
    }
}

/// Helper that binds lifecycle payloads to the prover backend circuit headers.
#[derive(Clone, Debug)]
pub struct ZsiBinder {
    operation: ZsiOperation,
    system: ProofSystemKind,
    circuit: String,
}

impl ZsiBinder {
    /// Construct a binder for the given backend and lifecycle operation.
    pub fn new<B: ProofBackend>(backend: &B, operation: ZsiOperation) -> Self {
        let system = system_kind(backend.name());
        let circuit = operation.circuit();
        Self {
            operation,
            system,
            circuit,
        }
    }

    /// Lifecycle operation attached to this binder.
    pub fn operation(&self) -> ZsiOperation {
        self.operation
    }

    fn witness_header(&self) -> WitnessHeader {
        WitnessHeader::new(self.system, self.circuit.clone())
    }

    fn proof_header(&self) -> ProofHeader {
        ProofHeader::new(self.system, self.circuit.clone())
    }

    /// Encode a witness payload using the lifecycle headers.
    pub fn encode_witness<T: Serialize>(&self, payload: &T) -> BackendResult<WitnessBytes> {
        WitnessBytes::encode(&self.witness_header(), payload)
    }

    /// Encode a proof payload using the lifecycle headers.
    pub fn encode_proof<T: Serialize>(&self, payload: &T) -> BackendResult<ProofBytes> {
        ProofBytes::encode(&self.proof_header(), payload)
    }
}
