use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use super::super::{ApiContext, ErrorResponse};
use crate::runtime::node::{ConsensusProofStatus, ConsensusProofVrfEntry};

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
    vrf_entries: Vec<ConsensusProofVrfEntry>,
    witness_commitments: Vec<String>,
    reputation_roots: Vec<String>,
    quorum_bitmap_root: String,
    quorum_signature_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf_outputs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf_proofs: Option<Vec<String>>,
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
    let version = requested.max(1).min(3);
    let include_extended = version >= 2;
    let include_legacy = version <= 2;

    let node = state.require_node()?;
    let status = node
        .consensus_proof_status()
        .map_err(|err| consensus_proof_error(&state, err))?;

    let Some(status) = status else {
        return Err(consensus_finality_unavailable(&state));
    };

    let legacy_outputs = status.legacy_vrf_outputs();
    let legacy_proofs = status.legacy_vrf_proofs();

    let ConsensusProofStatus {
        height,
        round,
        block_hash,
        total_power,
        quorum_threshold,
        prevote_power,
        precommit_power,
        commit_power,
        epoch,
        slot,
        mut vrf_entries,
        witness_commitments,
        reputation_roots,
        quorum_bitmap_root,
        quorum_signature_root,
        vrf_output,
        vrf_proof,
        witness_commitment_root,
        reputation_root,
        quorum_bitmap,
        quorum_signature,
    } = status;

    if version < 3 {
        for entry in &mut vrf_entries {
            entry.bindings = None;
        }
    }

    let payload = ConsensusProofStatusPayload {
        height,
        round,
        block_hash,
        total_power,
        quorum_threshold,
        prevote_power,
        precommit_power,
        commit_power,
        epoch,
        slot,
        vrf_entries,
        witness_commitments,
        reputation_roots,
        quorum_bitmap_root,
        quorum_signature_root,
        vrf_outputs: include_legacy.then_some(legacy_outputs),
        vrf_proofs: include_legacy.then_some(legacy_proofs),
        vrf_output: include_extended.then_some(vrf_output),
        vrf_proof: include_extended.then_some(vrf_proof),
        witness_commitment_root: include_extended.then_some(witness_commitment_root),
        reputation_root: include_extended.then_some(reputation_root),
        quorum_bitmap: include_extended.then_some(quorum_bitmap),
        quorum_signature: include_extended.then_some(quorum_signature),
    };

    Ok(Json(ConsensusProofStatusResponse {
        version,
        status: payload,
    }))
}

fn consensus_finality_unavailable(state: &ApiContext) -> (StatusCode, Json<ErrorResponse>) {
    state.metrics().record_consensus_rpc_failure(
        crate::runtime::telemetry::metrics::ConsensusRpcFailure::FinalityGap,
    );

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse::with_code(
            "no consensus certificate recorded",
            crate::rpc::RpcErrorCode::ConsensusFinalityUnavailable,
        )),
    )
}

fn consensus_proof_error(
    state: &ApiContext,
    err: crate::runtime::errors::ChainError,
) -> (StatusCode, Json<ErrorResponse>) {
    state.metrics().record_consensus_rpc_failure(
        crate::runtime::telemetry::metrics::ConsensusRpcFailure::VerifierFailed,
    );

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse::with_code(
            err.to_string(),
            crate::rpc::RpcErrorCode::ConsensusVerifierFailed,
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use opentelemetry::global;
    use opentelemetry::metrics::noop::NoopMeterProvider;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rpp_runtime::RuntimeMetrics;

    use crate::runtime::errors::ChainError;
    use crate::RuntimeMode;

    fn context_with_metrics(exporter: &InMemoryMetricExporter) -> (ApiContext, SdkMeterProvider) {
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        global::set_meter_provider(provider.clone());

        let meter = provider.meter("rpp-runtime");
        let metrics = Arc::new(RuntimeMetrics::from_meter_for_testing(&meter));

        let context = ApiContext::new(
            Arc::new(parking_lot::RwLock::new(RuntimeMode::Node)),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            false,
        )
        .with_metrics(metrics);

        (context, provider)
    }

    fn collect_failure_counts(
        exporter: &InMemoryMetricExporter,
    ) -> std::collections::HashMap<String, u64> {
        let exported = exporter
            .get_finished_metrics()
            .expect("export consensus RPC metrics");

        let mut sums = std::collections::HashMap::new();
        for resource in &exported {
            for scope in &resource.scope_metrics {
                for metric in &scope.metrics {
                    if metric.name == "rpp.runtime.consensus.rpc.failures" {
                        if let opentelemetry_sdk::metrics::data::Data::Sum(sum) = &metric.data {
                            for point in &sum.points {
                                let key = point
                                    .attributes
                                    .iter()
                                    .map(|(k, v)| format!("{}={}", k.as_str(), v.to_string()))
                                    .collect::<Vec<_>>()
                                    .join(",");
                                sums.insert(key, point.value);
                            }
                        }
                    }
                }
            }
        }
        sums
    }

    #[test]
    fn finality_gap_surfaces_structured_code_and_metric() {
        let exporter = InMemoryMetricExporter::default();
        let (context, provider) = context_with_metrics(&exporter);

        let (status, Json(error)) = consensus_finality_unavailable(&context);
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, status);
        let encoded = serde_json::to_value(&error).expect("encode error");
        assert_eq!(
            Some("consensus_finality_unavailable"),
            encoded.get("code").and_then(|value| value.as_str())
        );

        provider.force_flush().unwrap();
        let counts = collect_failure_counts(&exporter);
        assert_eq!(Some(&1), counts.get("reason=finality_gap"));
    }

    #[test]
    fn verifier_failures_emit_code_and_metric() {
        let exporter = InMemoryMetricExporter::default();
        let (context, provider) = context_with_metrics(&exporter);

        let (status, Json(error)) =
            consensus_proof_error(&context, ChainError::Crypto("bad proof".into()));
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, status);
        let encoded = serde_json::to_value(&error).expect("encode error");
        assert_eq!(
            Some("consensus_verifier_failed"),
            encoded.get("code").and_then(|value| value.as_str())
        );

        provider.force_flush().unwrap();
        let counts = collect_failure_counts(&exporter);
        assert_eq!(Some(&1), counts.get("reason=verifier_failed"));
    }

    #[test]
    fn metrics_reset_on_drop() {
        global::set_meter_provider(NoopMeterProvider::new());
    }
}
