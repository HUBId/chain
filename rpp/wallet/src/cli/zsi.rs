use clap::{Args, Subcommand};
use prover_backend_interface::{BackendResult, ProofBackend};

use crate::proof_backend::Blake2sHasher;
use crate::wallet::{ZsiProofRequest, ZsiVerifyRequest};
use crate::zsi::{
    ConsensusApproval, LifecycleReceipt, RevokeRequest, RotateRequest, ZsiLifecycle, ZsiOperation,
    ZsiRecord, ZsiRequest,
};

fn parse_approval(value: &str) -> Result<ConsensusApproval, String> {
    let mut segments = value.splitn(3, ':');
    let validator = segments
        .next()
        .ok_or_else(|| "missing validator in approval".to_string())?;
    let signature = segments
        .next()
        .ok_or_else(|| "missing signature in approval".to_string())?;
    let timestamp = segments
        .next()
        .ok_or_else(|| "missing timestamp in approval".to_string())?
        .parse::<u64>()
        .map_err(|_| "invalid timestamp in approval".to_string())?;
    Ok(ConsensusApproval {
        validator: validator.to_string(),
        signature: signature.to_string(),
        timestamp,
    })
}

fn digest(value: &str) -> String {
    let hash: [u8; 32] = Blake2sHasher::hash(value.as_bytes()).into();
    hex::encode(hash)
}

fn parse_operation(value: &str) -> Result<ZsiOperation, String> {
    match value {
        "issue" => Ok(ZsiOperation::Issue),
        "rotate" => Ok(ZsiOperation::Rotate),
        "revoke" => Ok(ZsiOperation::Revoke),
        "audit" => Ok(ZsiOperation::Audit),
        other => Err(format!("unsupported operation `{other}`")),
    }
}

#[derive(Debug, Args)]
pub struct ZsiCli {
    #[command(subcommand)]
    pub command: ZsiSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ZsiSubcommand {
    /// Issue a new ZSI identity declaration.
    Issue {
        #[arg(long)]
        identity: String,
        #[arg(long)]
        genesis_id: String,
        #[arg(long)]
        attestation: String,
        #[arg(long = "approval", value_parser = parse_approval)]
        approvals: Vec<ConsensusApproval>,
    },
    /// Rotate an identity to a new genesis commitment.
    Rotate {
        #[arg(long)]
        identity: String,
        #[arg(long = "previous-genesis")]
        previous_genesis: String,
        #[arg(long = "previous-attestation")]
        previous_attestation: String,
        #[arg(long = "next-genesis")]
        next_genesis: String,
        #[arg(long)]
        attestation: Option<String>,
        #[arg(long = "approval", value_parser = parse_approval)]
        approvals: Vec<ConsensusApproval>,
    },
    /// Revoke an identity that has been compromised.
    Revoke {
        #[arg(long)]
        identity: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        attestation: Option<String>,
    },
    /// Audit the local registry representation of an identity.
    Audit {
        #[arg(long)]
        identity: String,
        #[arg(long)]
        genesis_id: String,
        #[arg(long)]
        attestation: String,
        #[arg(long = "approval", value_parser = parse_approval)]
        approvals: Vec<ConsensusApproval>,
    },
}

#[derive(Debug, Args)]
pub struct ZsiWalletCli {
    #[command(subcommand)]
    pub command: ZsiWalletSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ZsiWalletSubcommand {
    /// Generate a lifecycle proof using the configured wallet backend.
    Prove(ZsiWalletProveArgs),
    /// Verify an externally supplied lifecycle proof.
    Verify(ZsiWalletVerifyArgs),
    /// Bind an identity record to a witness and public inputs.
    #[command(name = "bind-account")]
    BindAccount(ZsiWalletBindArgs),
    /// List cached lifecycle proof artefacts.
    List,
    /// Delete a cached lifecycle proof artefact.
    Delete(ZsiWalletDeleteArgs),
}

#[derive(Clone, Debug, Args)]
pub struct ZsiWalletProofArgs {
    #[arg(long)]
    pub operation: String,
    #[arg(long)]
    pub identity: String,
    #[arg(long = "genesis-id")]
    pub genesis_id: String,
    #[arg(long)]
    pub attestation: String,
    #[arg(long = "approval", value_parser = parse_approval)]
    pub approvals: Vec<ConsensusApproval>,
}

#[derive(Clone, Debug, Args)]
pub struct ZsiWalletProveArgs {
    #[command(flatten)]
    pub proof: ZsiWalletProofArgs,
}

#[derive(Clone, Debug, Args)]
pub struct ZsiWalletBindArgs {
    #[command(flatten)]
    pub proof: ZsiWalletProofArgs,
}

#[derive(Clone, Debug, Args)]
pub struct ZsiWalletVerifyArgs {
    #[command(flatten)]
    pub proof: ZsiWalletProofArgs,
    #[arg(long = "proof")]
    pub proof_hex: String,
}

#[derive(Clone, Debug, Args)]
pub struct ZsiWalletDeleteArgs {
    #[arg(long)]
    pub identity: String,
    #[arg(long = "commitment")]
    pub commitment_digest: String,
}

impl ZsiWalletProofArgs {
    fn into_request(self) -> Result<ZsiProofRequest, String> {
        let operation = parse_operation(&self.operation)?;
        let record = ZsiRecord {
            identity: self.identity,
            genesis_id: self.genesis_id,
            attestation_digest: digest(&self.attestation),
            approvals: self.approvals,
        };
        Ok(ZsiProofRequest { operation, record })
    }
}

impl ZsiWalletProveArgs {
    pub fn into_request(self) -> Result<ZsiProofRequest, String> {
        self.proof.into_request()
    }
}

impl ZsiWalletBindArgs {
    pub fn into_request(self) -> Result<ZsiProofRequest, String> {
        self.proof.into_request()
    }
}

impl ZsiWalletVerifyArgs {
    pub fn into_request(self) -> Result<ZsiVerifyRequest, String> {
        let request = self.proof.into_request()?;
        let proof = hex::decode(self.proof_hex.trim_start_matches("0x"))
            .map_err(|err| format!("invalid proof hex: {err}"))?;
        Ok(ZsiVerifyRequest {
            operation: request.operation,
            record: request.record,
            proof,
        })
    }
}

pub fn execute<B: ProofBackend>(backend: B, cli: ZsiCli) -> BackendResult<LifecycleReceipt> {
    let lifecycle = ZsiLifecycle::new(backend);
    match cli.command {
        ZsiSubcommand::Issue {
            identity,
            genesis_id,
            attestation,
            approvals,
        } => lifecycle.issue(ZsiRequest {
            identity,
            genesis_id,
            attestation,
            approvals,
        }),
        ZsiSubcommand::Rotate {
            identity,
            previous_genesis,
            previous_attestation,
            next_genesis,
            attestation,
            approvals,
        } => {
            let previous = ZsiRecord {
                identity: identity.clone(),
                genesis_id: previous_genesis,
                attestation_digest: digest(&previous_attestation),
                approvals: approvals.clone(),
            };
            lifecycle.rotate(RotateRequest {
                previous,
                next_genesis_id: next_genesis,
                attestation,
                approvals,
            })
        }
        ZsiSubcommand::Revoke {
            identity,
            reason,
            attestation,
        } => lifecycle.revoke(RevokeRequest {
            identity,
            reason,
            attestation,
        }),
        ZsiSubcommand::Audit {
            identity,
            genesis_id,
            attestation,
            approvals,
        } => {
            let record = ZsiRecord {
                identity,
                genesis_id,
                attestation_digest: digest(&attestation),
                approvals,
            };
            lifecycle.audit(record)
        }
    }
}
