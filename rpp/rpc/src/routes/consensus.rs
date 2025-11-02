use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use super::super::{to_http_error, ApiContext, ErrorResponse};
use crate::runtime::node::ConsensusProofStatus;

#[derive(Debug, Default, Deserialize)]
pub(super) struct ConsensusProofStatusQuery {
    pub version: Option<u8>,
}

#[derive(Debug, Serialize)]
struct ConsensusProofStatusPayload {
    height: u64,
    round: u64,
    block_hash: String,
    total_power: String,
    quorum_threshold: String,
    prevote_power: String,
    precommit_power: String,
    commit_power: String,
    epoch: u64,
    slot: u64,
    vrf_outputs: Vec<String>,
    vrf_proofs: Vec<String>,
    witness_commitments: Vec<String>,
    reputation_roots: Vec<String>,
    quorum_bitmap_root: String,
    quorum_signature_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf_output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_commitment_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reputation_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_bitmap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConsensusProofStatusResponse {
    version: u8,
    #[serde(flatten)]
    status: ConsensusProofStatusPayload,
}

pub(super) async fn proof_status(
    State(state): State<ApiContext>,
    Query(query): Query<ConsensusProofStatusQuery>,
) -> Result<Json<ConsensusProofStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let requested = query.version.unwrap_or(2);
    let version = requested.max(1).min(2);
    let include_extended = version >= 2;

    let node = state.require_node()?;
    let status = node.consensus_proof_status().map_err(to_http_error)?;

    let Some(status) = status else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "no consensus certificate recorded".to_string(),
            }),
        ));
    };

    let payload = ConsensusProofStatusPayload {
        height: status.height,
        round: status.round,
        block_hash: status.block_hash,
        total_power: status.total_power,
        quorum_threshold: status.quorum_threshold,
        prevote_power: status.prevote_power,
        precommit_power: status.precommit_power,
        commit_power: status.commit_power,
        epoch: status.epoch,
        slot: status.slot,
        vrf_outputs: status.vrf_outputs,
        vrf_proofs: status.vrf_proofs,
        witness_commitments: status.witness_commitments,
        reputation_roots: status.reputation_roots,
        quorum_bitmap_root: status.quorum_bitmap_root,
        quorum_signature_root: status.quorum_signature_root,
        vrf_output: include_extended.then_some(status.vrf_output),
        vrf_proof: include_extended.then_some(status.vrf_proof),
        witness_commitment_root: include_extended.then_some(status.witness_commitment_root),
        reputation_root: include_extended.then_some(status.reputation_root),
        quorum_bitmap: include_extended.then_some(status.quorum_bitmap),
        quorum_signature: include_extended.then_some(status.quorum_signature),
    };

    Ok(Json(ConsensusProofStatusResponse {
        version,
        status: payload,
    }))
}
