#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use prover_mock_backend::MockBackend;
use rpp_wallet::zsi::{
    ConsensusApproval, RevokeRequest, RotateRequest, ZsiLifecycle, ZsiRecord, ZsiRequest,
};

type BackendResult<T> = prover_backend_interface::BackendResult<T>;

#[derive(Debug, Arbitrary)]
struct ApprovalInput {
    validator: String,
    signature: String,
    timestamp: u64,
}

impl ApprovalInput {
    fn into_consensus(self) -> ConsensusApproval {
        ConsensusApproval {
            validator: self.validator,
            signature: self.signature,
            timestamp: self.timestamp,
        }
    }
}

#[derive(Debug, Arbitrary)]
struct RecordInput {
    identity: String,
    genesis_id: String,
    attestation_digest: String,
    approvals: Vec<ApprovalInput>,
}

impl RecordInput {
    fn into_record(self) -> ZsiRecord {
        ZsiRecord {
            identity: self.identity,
            genesis_id: self.genesis_id,
            attestation_digest: self.attestation_digest,
            approvals: self
                .approvals
                .into_iter()
                .map(ApprovalInput::into_consensus)
                .collect(),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct RequestInput {
    identity: String,
    genesis_id: String,
    attestation: String,
    approvals: Vec<ApprovalInput>,
}

impl RequestInput {
    fn into_request(self) -> ZsiRequest {
        ZsiRequest {
            identity: self.identity,
            genesis_id: self.genesis_id,
            attestation: self.attestation,
            approvals: self
                .approvals
                .into_iter()
                .map(ApprovalInput::into_consensus)
                .collect(),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct RotateInput {
    previous: RecordInput,
    next_genesis_id: String,
    attestation: Option<String>,
    approvals: Vec<ApprovalInput>,
}

impl RotateInput {
    fn into_request(self) -> RotateRequest {
        RotateRequest {
            previous: self.previous.into_record(),
            next_genesis_id: self.next_genesis_id,
            attestation: self.attestation,
            approvals: self
                .approvals
                .into_iter()
                .map(ApprovalInput::into_consensus)
                .collect(),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct RevokeInput {
    identity: String,
    reason: String,
    attestation: Option<String>,
}

impl RevokeInput {
    fn into_request(self) -> RevokeRequest {
        RevokeRequest {
            identity: self.identity,
            reason: self.reason,
            attestation: self.attestation,
        }
    }
}

#[derive(Debug, Arbitrary)]
enum LifecycleOperation {
    Issue(RequestInput),
    Rotate(RotateInput),
    Revoke(RevokeInput),
    Audit(RecordInput),
}

#[derive(Debug, Arbitrary)]
struct LifecycleSequence {
    operations: Vec<LifecycleOperation>,
}

fn exercise_operation(
    lifecycle: &ZsiLifecycle<MockBackend>,
    operation: LifecycleOperation,
) -> BackendResult<()> {
    match operation {
        LifecycleOperation::Issue(input) => {
            let _ = lifecycle.issue(input.into_request())?;
        }
        LifecycleOperation::Rotate(input) => {
            let _ = lifecycle.rotate(input.into_request())?;
        }
        LifecycleOperation::Revoke(input) => {
            let _ = lifecycle.revoke(input.into_request())?;
        }
        LifecycleOperation::Audit(input) => {
            let _ = lifecycle.audit(input.into_record())?;
        }
    }
    Ok(())
}

fuzz_target!(|sequence: LifecycleSequence| {
    let backend = MockBackend::new();
    let lifecycle = ZsiLifecycle::new(backend);

    for operation in sequence.operations {
        if exercise_operation(&lifecycle, operation).is_err() {
            break;
        }
    }
});
