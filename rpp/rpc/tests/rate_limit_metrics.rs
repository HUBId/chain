use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{Metric, Sum};
use opentelemetry_sdk::metrics::readers::PeriodicReader;
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use reqwest::Client;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::oneshot;

use rpp::api;
use rpp::runtime::config::{NetworkLimitsConfig, NetworkTlsConfig};
use rpp::runtime::telemetry::metrics::RuntimeMetrics;
use rpp::runtime::RuntimeMode;

fn random_loopback() -> SocketAddr {
    let listener =
        TokioTcpListener::bind("127.0.0.1:0").expect("bind loopback for rate-limit metrics test");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

#[tokio::test]
async fn rate_limit_metrics_capture_method_and_status() {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(Resource::default())
        .build();
    let meter = provider.meter("rpc-rate-limit-metrics-test");
    let metrics = Arc::new(RuntimeMetrics::from_meter_for_testing(&meter));

    let addr = random_loopback();
    let mut limits = NetworkLimitsConfig::default();
    limits.per_ip_token_bucket.enabled = false;
    let request_limit = NonZeroU64::new(1).expect("non-zero rate limit");
    let (shutdown_tx, handle) = spawn_server_with_metrics(
        addr,
        limits,
        NetworkTlsConfig::default(),
        request_limit,
        metrics,
    )
    .await;

    let client = Client::builder().build().expect("client");

    let health = format!("http://{addr}/health");
    let proof = format!("http://{addr}/proofs/block/0");

    let _ = client
        .get(&health)
        .header("Authorization", "Bearer tenant-a")
        .send()
        .await
        .expect("first health request");
    let throttled_health = client
        .get(&health)
        .header("Authorization", "Bearer tenant-a")
        .send()
        .await
        .expect("second health request");
    assert_eq!(
        throttled_health.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
    );

    let _ = client
        .get(&proof)
        .header("Authorization", "Bearer tenant-b")
        .send()
        .await
        .expect("first proof request");
    let throttled_proof = client
        .get(&proof)
        .header("Authorization", "Bearer tenant-b")
        .send()
        .await
        .expect("second proof request");
    assert_eq!(
        throttled_proof.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;

    provider
        .force_flush()
        .expect("flush rate-limit metrics before assertions");
    let exported = exporter
        .get_finished_metrics()
        .expect("finished rate-limit metrics");

    let rate_limit_counts = extract_rate_limit_counts(exported);

    assert_eq!(
        rate_limit_counts
            .get(&("other".to_string(), "allowed".to_string()))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&("other".to_string(), "throttled".to_string()))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&("proof".to_string(), "allowed".to_string()))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&("proof".to_string(), "throttled".to_string()))
            .copied(),
        Some(1)
    );
}

async fn spawn_server_with_metrics(
    addr: SocketAddr,
    limits: NetworkLimitsConfig,
    tls: NetworkTlsConfig,
    request_limit_per_minute: NonZeroU64,
    metrics: Arc<RuntimeMetrics>,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let context = api::ApiContext::new(
        Arc::new(parking_lot::RwLock::new(RuntimeMode::Node)),
        None,
        None,
        None,
        Some(request_limit_per_minute),
        false,
        None,
        None,
        false,
    )
    .with_metrics(metrics);

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        let _ = api::serve_with_shutdown(
            context,
            addr,
            None,
            None,
            limits,
            tls,
            shutdown,
            Some(ready_tx),
        )
        .await;
    });

    ready_rx.await.expect("server ready").expect("server start");

    (shutdown_tx, handle)
}

fn extract_rate_limit_counts(
    exported: Vec<opentelemetry_sdk::metrics::data::ResourceMetrics>,
) -> std::collections::HashMap<(String, String), u64> {
    let mut counts = std::collections::HashMap::new();

    for resource in exported {
        for scope in resource.scope_metrics {
            for metric in scope.metrics {
                if metric.name != "rpp.runtime.rpc.rate_limit.total" {
                    continue;
                }

                if let Metric::Sum(Sum { data_points, .. }) = metric.data {
                    for point in data_points {
                        let mut method = None;
                        let mut status = None;
                        for KeyValue { key, value } in point.attributes {
                            match key.as_str() {
                                "method" => method = Some(value.to_string()),
                                "status" => status = Some(value.to_string()),
                                _ => {}
                            }
                        }

                        if let (Some(method), Some(status)) = (method, status) {
                            counts.insert((method, status), point.value);
                        }
                    }
                }
            }
        }
    }

    counts
}
