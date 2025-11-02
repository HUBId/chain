//! Regression coverage for proof IO errors surfaced during state-sync chunk streaming.
//!
//! Relies on the shared harness in [`support::StateSyncFixture`](support/mod.rs) to
//! configure the node runtime for test scenarios.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request as HttpRequest, StatusCode},
    routing::get,
    Router,
};
use hyper::body::to_bytes;
use opentelemetry::{global, Value};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::{
    InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider,
};
use parking_lot::RwLock;
use rpp_chain::api::{routes, ApiContext, ErrorResponse, RpcMetricsLayer};
use rpp_chain::runtime::metrics::RuntimeMetrics;
use rpp_chain::runtime::RuntimeMode;
#[path = "support/mod.rs"]
mod support;

use support::StateSyncFixture;
use tower::ServiceExt;

#[tokio::test]
async fn state_sync_chunk_surfaces_proof_error_io() -> Result<(), MetricError> {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let cache = fixture.failing_session_cache();
    handle.install_state_sync_session_cache_for_tests(cache);

    let (metrics, exporter, provider) = setup_metrics();

    let context = ApiContext::new(
        Arc::new(RwLock::new(RuntimeMode::Node)),
        Some(handle.clone()),
        None,
        None,
        None,
        false,
        None,
        None,
        false,
    )
    .with_metrics(metrics.clone())
    .with_state_sync_api(Arc::new(handle.clone()));

    let app = Router::new()
        .route(
            "/state-sync/chunk/:id",
            get(routes::state_sync::chunk_by_id),
        )
        .layer(RpcMetricsLayer::new(metrics))
        .with_state(context);

    let request = HttpRequest::builder()
        .uri("/state-sync/chunk/0")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let bytes = to_bytes(response.into_body()).await.unwrap();
    let error: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(
        error.error.starts_with("ProofError::IO("),
        "unexpected error message: {}",
        error.error
    );

    provider.force_flush()?;
    let exported = exporter.get_finished_metrics()?;

    assert!(metric_has_attributes(
        &exported,
        "rpp.runtime.rpc.request.total",
        "other",
        "server_error",
    ));
    assert!(metric_has_attributes(
        &exported,
        "rpp.runtime.rpc.request.latency",
        "other",
        "server_error",
    ));
    assert!(metric_has_value(
        &exported,
        "rpp_node_pipeline_root_io_errors_total",
        1,
    ));

    Ok(())
}

fn setup_metrics() -> (
    Arc<RuntimeMetrics>,
    InMemoryMetricExporter,
    Arc<SdkMeterProvider>,
) {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = Arc::new(SdkMeterProvider::builder().with_reader(reader).build());
    global::set_meter_provider(provider.clone());
    let meter = provider.meter("rpc-test");
    let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));
    (metrics, exporter, provider)
}

fn metric_has_attributes(
    exported: &[ResourceMetrics],
    name: &str,
    method: &str,
    result: &str,
) -> bool {
    exported
        .iter()
        .flat_map(|resource| resource.scope_metrics())
        .flat_map(|scope| scope.metrics())
        .filter(|metric| metric.name() == name)
        .any(|metric| match metric.data() {
            AggregatedMetrics::F64(MetricData::Histogram(histogram)) => histogram
                .data_points()
                .any(|point| data_point_matches(point.attributes(), method, result)),
            AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                .data_points()
                .any(|point| data_point_matches(point.attributes(), method, result)),
            _ => false,
        })
}

fn metric_has_value(exported: &[ResourceMetrics], name: &str, expected: u64) -> bool {
    exported
        .iter()
        .flat_map(|resource| resource.scope_metrics())
        .flat_map(|scope| scope.metrics())
        .filter(|metric| metric.name() == name)
        .any(|metric| match metric.data() {
            AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                sum.data_points().any(|point| point.value() >= expected)
            }
            _ => false,
        })
}

fn data_point_matches<'a>(
    attrs: impl Iterator<Item = &'a opentelemetry::KeyValue>,
    method: &str,
    result: &str,
) -> bool {
    let mut method_match = false;
    let mut result_match = false;

    for attr in attrs {
        match attr.key.as_str() {
            "method" => {
                if let Value::String(value) = &attr.value {
                    method_match = value.as_str() == method;
                }
            }
            "result" => {
                if let Value::String(value) = &attr.value {
                    result_match = value.as_str() == result;
                }
            }
            _ => {}
        }
    }

    method_match && result_match
}
