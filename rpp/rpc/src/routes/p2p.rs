use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
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
use rpp_p2p::{
    AdmissionApproval, AdmissionAuditTrail, AdmissionPolicies, AdmissionPolicyLogEntry,
    AllowlistedPeer, TierLevel,
};

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
    #[serde(default)]
    pub plan_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotStreamStatusResponse {
    pub session: u64,
    pub peer: String,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AdmissionPoliciesResponse {
    pub allowlist: Vec<AdmissionPolicyEntry>,
    pub blocklist: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdmissionAuditLogQuery {
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdmissionAuditLogResponse {
    pub offset: usize,
    pub limit: usize,
    pub total: usize,
    pub entries: Vec<AdmissionPolicyLogEntry>,
}

#[derive(Debug, Serialize)]
pub struct AdmissionBackupMetadata {
    pub name: String,
    pub timestamp_ms: u64,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct AdmissionBackupsResponse {
    pub backups: Vec<AdmissionBackupMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct AdmissionBackupQuery {
    #[serde(default)]
    pub download: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdmissionApprovalRequest {
    pub role: String,
    pub approver: String,
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
    #[serde(default)]
    pub approvals: Vec<AdmissionApprovalRequest>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreAdmissionBackupRequest {
    pub backup: String,
    pub actor: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub approvals: Vec<AdmissionApprovalRequest>,
}

impl From<SnapshotStreamStatus> for SnapshotStreamStatusResponse {
    fn from(status: SnapshotStreamStatus) -> Self {
        let plan_id = status
            .plan_id
            .clone()
            .or_else(|| (!status.root.is_empty()).then(|| status.root.clone()));
        Self {
            session: status.session.get(),
            peer: status.peer.to_string(),
            root: status.root,
            plan_id,
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

    let plan_id = match request.resume.as_ref() {
        Some(marker) => {
            let value = marker
                .plan_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    super::super::bad_request(
                        "resume.plan_id must be provided when resuming a snapshot",
                    )
                })?;
            Some(value.to_owned())
        }
        None => None,
    };

    let root_hint = plan_id.clone().unwrap_or_default();

    let runtime = state.require_snapshot_runtime()?;
    let status = runtime
        .start_snapshot_stream(session, peer, root_hint)
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

pub(super) async fn cancel_snapshot_stream(
    State(state): State<ApiContext>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let session = id
        .parse::<u64>()
        .map_err(|err| super::super::bad_request(format!("invalid snapshot session id: {err}")))?;

    let runtime = state.require_snapshot_runtime()?;
    runtime
        .cancel_snapshot_stream(session)
        .await
        .map_err(snapshot_runtime_error_to_http)?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn admission_policies(
    State(state): State<ApiContext>,
) -> Result<Json<AdmissionPoliciesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let policies = node.admission_policies();
    Ok(Json(AdmissionPoliciesResponse::from(policies)))
}

pub(super) async fn admission_backups(
    State(state): State<ApiContext>,
    Query(query): Query<AdmissionBackupQuery>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    if let Some(name) = query.download {
        let data = node.admission_policy_backup(&name).map_err(to_http_error)?;
        let mut response = Response::new(Body::from(data));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let disposition = format!("attachment; filename=\"{}\"", name);
        if let Ok(value) = HeaderValue::from_str(&disposition) {
            response
                .headers_mut()
                .insert(header::CONTENT_DISPOSITION, value);
        }
        return Ok(response);
    }

    let backups = node.admission_policy_backups().map_err(to_http_error)?;
    let payload = AdmissionBackupsResponse {
        backups: backups
            .into_iter()
            .map(|backup| AdmissionBackupMetadata {
                name: backup.name,
                timestamp_ms: backup.timestamp_ms,
                size: backup.size,
            })
            .collect(),
    };
    Ok(Json(payload).into_response())
}

pub(super) async fn restore_admission_backup(
    State(state): State<ApiContext>,
    Json(request): Json<RestoreAdmissionBackupRequest>,
) -> Result<Json<AdmissionPoliciesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;

    let backup = request.backup.trim();
    if backup.is_empty() {
        return Err(super::super::bad_request("backup must not be empty"));
    }
    let backup = backup.to_string();

    let actor = request.actor.trim();
    if actor.is_empty() {
        return Err(super::super::bad_request("actor must not be empty"));
    }
    let actor = actor.to_string();

    let reason = request
        .reason
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let mut approvals = Vec::with_capacity(request.approvals.len());
    let mut approval_roles = HashSet::new();
    for approval in request.approvals {
        let role = approval.role.trim();
        if role.is_empty() {
            return Err(super::super::bad_request("approval role must not be empty"));
        }
        let approver = approval.approver.trim();
        if approver.is_empty() {
            return Err(super::super::bad_request(format!(
                "approval `{role}` must include approver"
            )));
        }
        let normalized = role.to_ascii_lowercase();
        if !approval_roles.insert(normalized.clone()) {
            return Err(super::super::bad_request(format!(
                "duplicate approval role `{role}`"
            )));
        }
        approvals.push(AdmissionApproval::new(
            role.to_string(),
            approver.to_string(),
        ));
    }

    let audit = AdmissionAuditTrail::new(actor, reason).with_approvals(approvals);
    node.restore_admission_policies_from_backup(&backup, audit)
        .map_err(to_http_error)?;

    let policies = node.admission_policies();
    Ok(Json(AdmissionPoliciesResponse::from(policies)))
}

pub(super) async fn update_admission_policies(
    State(state): State<ApiContext>,
    Json(request): Json<UpdateAdmissionPoliciesRequest>,
) -> Result<Json<AdmissionPoliciesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let current = node.admission_policies();

    let actor = request.actor.trim().to_string();
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

    let mut approvals = Vec::with_capacity(request.approvals.len());
    let mut approval_roles = HashSet::new();
    for approval in request.approvals {
        let role = approval.role.trim();
        if role.is_empty() {
            return Err(super::super::bad_request("approval role must not be empty"));
        }
        let approver = approval.approver.trim();
        if approver.is_empty() {
            return Err(super::super::bad_request(format!(
                "approval `{role}` must include approver"
            )));
        }
        let normalized = role.to_ascii_lowercase();
        if !approval_roles.insert(normalized.clone()) {
            return Err(super::super::bad_request(format!(
                "duplicate approval role `{role}`"
            )));
        }
        approvals.push(AdmissionApproval::new(
            role.to_string(),
            approver.to_string(),
        ));
    }

    let high_impact = admission_policies_changed(
        current.allowlist(),
        &allowlist,
        current.blocklist(),
        &blocklist,
    );

    if high_impact {
        let mut missing = Vec::new();
        for role in ["operations", "security"] {
            if !approvals
                .iter()
                .any(|approval| approval.role().eq_ignore_ascii_case(role))
            {
                missing.push(role);
            }
        }
        if !missing.is_empty() {
            return Err(super::super::bad_request(format!(
                "missing required approvals: {}",
                missing.join(", ")
            )));
        }
    }

    #[cfg(test)]
    if let Some(peerstore) = state.test_peerstore() {
        let audit = AdmissionAuditTrail::new(actor.clone(), reason.clone())
            .with_approvals(approvals.clone());
        peerstore
            .update_admission_policies(allowlist.clone(), blocklist.clone(), audit)
            .map_err(to_http_error)?;
        let policies = peerstore.admission_policies();
        return Ok(Json(AdmissionPoliciesResponse::from(policies)));
    }

    let audit = AdmissionAuditTrail::new(actor, reason).with_approvals(approvals);
    node.update_admission_policies(allowlist, blocklist, audit)
        .map_err(to_http_error)?;

    let policies = node.admission_policies();
    Ok(Json(AdmissionPoliciesResponse::from(policies)))
}

pub(super) async fn admission_audit_log(
    State(state): State<ApiContext>,
    Query(query): Query<AdmissionAuditLogQuery>,
) -> Result<Json<AdmissionAuditLogResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(200);
    if limit == 0 {
        return Ok(Json(AdmissionAuditLogResponse {
            offset,
            limit,
            total: 0,
            entries: Vec::new(),
        }));
    }
    #[cfg(test)]
    if let Some(peerstore) = state.test_peerstore() {
        let (entries, total) = peerstore
            .admission_audit_entries(offset, limit)
            .map_err(to_http_error)?;
        return Ok(Json(AdmissionAuditLogResponse {
            offset,
            limit,
            total,
            entries,
        }));
    }
    let (entries, total) = node
        .admission_audit_log(offset, limit)
        .map_err(to_http_error)?;
    Ok(Json(AdmissionAuditLogResponse {
        offset,
        limit,
        total,
        entries,
    }))
}

fn admission_policies_changed(
    current_allowlist: &[AllowlistedPeer],
    next_allowlist: &[AllowlistedPeer],
    current_blocklist: &[NetworkPeerId],
    next_blocklist: &[NetworkPeerId],
) -> bool {
    if blocklist_snapshot(current_blocklist) != blocklist_snapshot(next_blocklist) {
        return true;
    }
    allowlist_snapshot(current_allowlist) != allowlist_snapshot(next_allowlist)
}

fn blocklist_snapshot(entries: &[NetworkPeerId]) -> HashSet<NetworkPeerId> {
    entries.iter().cloned().collect()
}

fn allowlist_snapshot(entries: &[AllowlistedPeer]) -> BTreeMap<NetworkPeerId, TierLevel> {
    entries
        .iter()
        .map(|entry| (entry.peer.clone(), entry.tier))
        .collect()
}
