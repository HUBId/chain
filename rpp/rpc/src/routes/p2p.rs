use std::collections::HashSet;
use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::{
    snapshot_runtime_error_to_http, to_http_error, ApiContext, ErrorResponse,
    SnapshotStreamRuntimeError,
};
use crate::runtime::node_runtime::node::SnapshotStreamStatus;
use rpp_p2p::vendor::PeerId as NetworkPeerId;
use rpp_p2p::{AdmissionAuditTrail, AdmissionPolicies, AllowlistedPeer, TierLevel};

#[derive(Debug, Deserialize)]
pub struct StartSnapshotStreamRequest {
    pub peer: String,
    pub chunk_size: u32,
    #[serde(default)]
    pub resume: Option<ResumeMarker>,
}

#[derive(Debug, Deserialize)]
pub struct ResumeMarker {
    pub session: u64,
}

#[derive(Debug, Serialize)]
pub struct SnapshotStreamStatusResponse {
    pub session: u64,
    pub peer: String,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chunk_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicyEntry {
    pub peer_id: String,
    pub tier: TierLevel,
}

#[derive(Debug, Serialize)]
pub struct AdmissionPoliciesResponse {
    pub allowlist: Vec<AdmissionPolicyEntry>,
    pub blocklist: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAdmissionPoliciesRequest {
    #[serde(default)]
    pub allowlist: Vec<AdmissionPolicyEntry>,
    #[serde(default)]
    pub blocklist: Vec<String>,
    pub actor: String,
    #[serde(default)]
    pub reason: Option<String>,
}

impl From<SnapshotStreamStatus> for SnapshotStreamStatusResponse {
    fn from(status: SnapshotStreamStatus) -> Self {
        Self {
            session: status.session.get(),
            peer: status.peer.to_string(),
            root: status.root,
            last_chunk_index: status.last_chunk_index,
            last_update_index: status.last_update_index,
            last_update_height: status.last_update_height,
            verified: status.verified,
            error: status.error,
        }
    }
}

impl From<AdmissionPolicies> for AdmissionPoliciesResponse {
    fn from(policies: AdmissionPolicies) -> Self {
        let allowlist = policies
            .allowlist
            .into_iter()
            .map(|entry| AdmissionPolicyEntry {
                peer_id: entry.peer.to_base58(),
                tier: entry.tier,
            })
            .collect();
        let mut blocklist: Vec<String> = policies
            .blocklist
            .into_iter()
            .map(|peer| peer.to_base58())
            .collect();
        blocklist.sort();
        Self {
            allowlist,
            blocklist,
        }
    }
}

fn next_session_id() -> u64 {
    let uuid = Uuid::new_v4().as_u128();
    (uuid & u64::MAX as u128) as u64
}

pub(super) async fn start_snapshot_stream(
    State(state): State<ApiContext>,
    Json(request): Json<StartSnapshotStreamRequest>,
) -> Result<Json<SnapshotStreamStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    if request.chunk_size == 0 {
        return Err(super::super::bad_request(
            "chunk_size must be greater than zero",
        ));
    }

    let peer = NetworkPeerId::from_str(request.peer.trim())
        .map_err(|err| super::super::bad_request(format!("invalid peer id: {err}")))?;

    let session = request
        .resume
        .as_ref()
        .map(|marker| marker.session)
        .unwrap_or_else(next_session_id);

    let runtime = state.require_snapshot_runtime()?;
    let status = runtime
        .start_snapshot_stream(session, peer, String::new())
        .await
        .map_err(snapshot_runtime_error_to_http)?;

    Ok(Json(SnapshotStreamStatusResponse::from(status)))
}

pub(super) async fn snapshot_stream_status(
    State(state): State<ApiContext>,
    Path(id): Path<String>,
) -> Result<Json<SnapshotStreamStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let session = id
        .parse::<u64>()
        .map_err(|err| super::super::bad_request(format!("invalid snapshot session id: {err}")))?;

    let runtime = state.require_snapshot_runtime()?;
    let status = runtime.snapshot_stream_status(session).ok_or_else(|| {
        snapshot_runtime_error_to_http(SnapshotStreamRuntimeError::SessionNotFound(session))
    })?;

    Ok(Json(SnapshotStreamStatusResponse::from(status)))
}

pub(super) async fn admission_policies(
    State(state): State<ApiContext>,
) -> Result<Json<AdmissionPoliciesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let policies = node.admission_policies();
    Ok(Json(AdmissionPoliciesResponse::from(policies)))
}

pub(super) async fn update_admission_policies(
    State(state): State<ApiContext>,
    Json(request): Json<UpdateAdmissionPoliciesRequest>,
) -> Result<Json<AdmissionPoliciesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let actor = request.actor.trim();
    if actor.is_empty() {
        return Err(super::super::bad_request("actor must not be empty"));
    }

    let reason = request
        .reason
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let mut allowlist = Vec::with_capacity(request.allowlist.len());
    let mut allow_seen = HashSet::new();
    for entry in request.allowlist {
        let peer = NetworkPeerId::from_str(&entry.peer_id).map_err(|err| {
            super::super::bad_request(format!("invalid allowlist peer `{}`: {err}", entry.peer_id))
        })?;
        if !allow_seen.insert(peer.clone()) {
            return Err(super::super::bad_request(format!(
                "duplicate allowlist entry for peer `{}`",
                entry.peer_id
            )));
        }
        allowlist.push(AllowlistedPeer {
            peer,
            tier: entry.tier,
        });
    }

    let mut blocklist = Vec::with_capacity(request.blocklist.len());
    let mut block_seen = HashSet::new();
    for value in request.blocklist {
        let peer = NetworkPeerId::from_str(&value).map_err(|err| {
            super::super::bad_request(format!("invalid blocklist peer `{value}`: {err}"))
        })?;
        if !block_seen.insert(peer.clone()) {
            return Err(super::super::bad_request(format!(
                "duplicate blocklist entry for peer `{value}`"
            )));
        }
        blocklist.push(peer);
    }

    for entry in &allowlist {
        if block_seen.contains(&entry.peer) {
            return Err(super::super::bad_request(format!(
                "peer `{}` cannot be in allowlist and blocklist",
                entry.peer.to_base58()
            )));
        }
    }

    let audit = AdmissionAuditTrail::new(actor, reason);
    node.update_admission_policies(allowlist, blocklist, audit)
        .map_err(to_http_error)?;

    let policies = node.admission_policies();
    Ok(Json(AdmissionPoliciesResponse::from(policies)))
}
