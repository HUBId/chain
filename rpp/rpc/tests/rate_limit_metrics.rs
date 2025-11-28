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
    limits.per_ip_token_bucket.read.enabled = false;
    limits.per_ip_token_bucket.write.enabled = false;
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
    let transactions = format!("http://{addr}/transactions");

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

    let _ = client
        .post(&transactions)
        .header("Authorization", "Bearer tenant-c")
        .body("{}")
        .send()
        .await
        .expect("first transaction request");
    let throttled_tx = client
        .post(&transactions)
        .header("Authorization", "Bearer tenant-c")
        .body("{}")
        .send()
        .await
        .expect("second transaction request");
    assert_eq!(
        throttled_tx.status(),
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
    let backend = "unspecified".to_string();

    assert_eq!(
        rate_limit_counts
            .get(&(
                backend.clone(),
                "read".to_string(),
                "other".to_string(),
                "allowed".to_string(),
                "tenant-a".to_string(),
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&(
                backend.clone(),
                "read".to_string(),
                "other".to_string(),
                "throttled".to_string(),
                "tenant-a".to_string(),
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&(
                backend.clone(),
                "read".to_string(),
                "proof".to_string(),
                "allowed".to_string(),
                "tenant-b".to_string(),
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&(
                backend.clone(),
                "read".to_string(),
                "proof".to_string(),
                "throttled".to_string(),
                "tenant-b".to_string(),
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&(
                backend.clone(),
                "write".to_string(),
                "other".to_string(),
                "allowed".to_string(),
                "tenant-c".to_string(),
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        rate_limit_counts
            .get(&(
                backend,
                "write".to_string(),
                "other".to_string(),
                "throttled".to_string(),
                "tenant-c".to_string(),
            ))
            .copied(),
        Some(1)
    );
}

#[tokio::test]
async fn tenants_are_isolated_across_backends() {
    let exporter_stark = InMemoryMetricExporter::default();
    let exporter_stwo = InMemoryMetricExporter::default();

    let reader_stark = PeriodicReader::builder(exporter_stark.clone()).build();
    let reader_stwo = PeriodicReader::builder(exporter_stwo.clone()).build();

    let provider_stark = SdkMeterProvider::builder()
        .with_reader(reader_stark)
        .with_resource(Resource::new(vec![KeyValue::new(
            "zk_backend",
            "rpp-stark",
        )]))
        .build();
    let provider_stwo = SdkMeterProvider::builder()
        .with_reader(reader_stwo)
        .with_resource(Resource::new(vec![KeyValue::new("zk_backend", "stwo")]))
        .build();

    let meter_stark = provider_stark.meter("rpc-rate-limit-metrics-backend-stark");
    let meter_stwo = provider_stwo.meter("rpc-rate-limit-metrics-backend-stwo");

    let metrics_stark = Arc::new(RuntimeMetrics::from_meter_for_testing(&meter_stark));
    let metrics_stwo = Arc::new(RuntimeMetrics::from_meter_for_testing(&meter_stwo));

    let addr_stark = random_loopback();
    let addr_stwo = random_loopback();
    let mut limits = NetworkLimitsConfig::default();
    limits.per_ip_token_bucket.read.enabled = false;
    limits.per_ip_token_bucket.write.enabled = false;
    let request_limit = NonZeroU64::new(1).expect("non-zero rate limit");

    let (shutdown_stark, handle_stark) = spawn_server_with_metrics(
        addr_stark,
        limits.clone(),
        NetworkTlsConfig::default(),
        request_limit,
        metrics_stark.clone(),
    )
    .await;
    let (shutdown_stwo, handle_stwo) = spawn_server_with_metrics(
        addr_stwo,
        limits,
        NetworkTlsConfig::default(),
        request_limit,
        metrics_stwo.clone(),
    )
    .await;

    let client = Client::builder().build().expect("client");

    let health_stark = format!("http://{addr_stark}/health");
    let health_stwo = format!("http://{addr_stwo}/health");

    let _ = client
        .get(&health_stark)
        .header("Authorization", "Bearer tenant-alpha")
        .send()
        .await
        .expect("first tenant alpha on rpp-stark");
    let throttled_stark = client
        .get(&health_stark)
        .header("Authorization", "Bearer tenant-alpha")
        .send()
        .await
        .expect("throttled tenant alpha on rpp-stark");
    assert_eq!(
        throttled_stark.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
    );
    assert_eq!(
        throttled_stark
            .headers()
            .get("x-ratelimit-tenant")
            .and_then(|value| value.to_str().ok()),
        Some("tenant-alpha"),
    );

    let _ = client
        .get(&health_stwo)
        .header("Authorization", "Bearer tenant-alpha")
        .send()
        .await
        .expect("first tenant alpha on stwo");
    let throttled_stwo = client
        .get(&health_stwo)
        .header("Authorization", "Bearer tenant-alpha")
        .send()
        .await
        .expect("throttled tenant alpha on stwo");
    assert_eq!(
        throttled_stwo.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
    );
    assert_eq!(
        throttled_stwo
            .headers()
            .get("x-ratelimit-tenant")
            .and_then(|value| value.to_str().ok()),
        Some("tenant-alpha"),
    );

    let tenant_beta = client
        .get(&health_stark)
        .header("Authorization", "Bearer tenant-beta")
        .send()
        .await
        .expect("tenant beta on rpp-stark");
    assert!(tenant_beta.status().is_success());

    let _ = shutdown_stark.send(());
    let _ = shutdown_stwo.send(());
    let _ = handle_stark.await;
    let _ = handle_stwo.await;

    provider_stark
        .force_flush()
        .expect("flush rpp-stark rate limit metrics");
    provider_stwo
        .force_flush()
        .expect("flush stwo rate limit metrics");

    let stark_counts = extract_rate_limit_counts(
        exporter_stark
            .get_finished_metrics()
            .expect("stark rate-limit metrics"),
    );
    let stwo_counts = extract_rate_limit_counts(
        exporter_stwo
            .get_finished_metrics()
            .expect("stwo rate-limit metrics"),
    );

    assert!(
        stark_counts
            .keys()
            .all(|(backend, _, _, _, _)| backend == "rpp-stark"),
        "stark counts should use rpp-stark backend label"
    );
    assert!(
        stwo_counts
            .keys()
            .all(|(backend, _, _, _, _)| backend == "stwo"),
        "stwo counts should use stwo backend label"
    );

    assert_eq!(
        stark_counts
            .get(&(
                "rpp-stark".into(),
                "read".into(),
                "other".into(),
                "allowed".into(),
                "tenant-alpha".into()
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        stark_counts
            .get(&(
                "rpp-stark".into(),
                "read".into(),
                "other".into(),
                "throttled".into(),
                "tenant-alpha".into()
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        stark_counts
            .get(&(
                "rpp-stark".into(),
                "read".into(),
                "other".into(),
                "allowed".into(),
                "tenant-beta".into()
            ))
            .copied(),
        Some(1)
    );

    assert_eq!(
        stwo_counts
            .get(&(
                "stwo".into(),
                "read".into(),
                "other".into(),
                "allowed".into(),
                "tenant-alpha".into()
            ))
            .copied(),
        Some(1)
    );
    assert_eq!(
        stwo_counts
            .get(&(
                "stwo".into(),
                "read".into(),
                "other".into(),
                "throttled".into(),
                "tenant-alpha".into()
            ))
            .copied(),
        Some(1)
    );
    assert!(
        stwo_counts
            .keys()
            .all(|(_, _, _, _, tenant)| tenant == "tenant-alpha"),
        "stwo backend should not see other tenant buckets"
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
) -> std::collections::HashMap<(String, String, String, String, String), u64> {
    let mut counts = std::collections::HashMap::new();

    for resource in exported {
        let backend = resource
            .resource
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "zk_backend")
            .map(|attribute| attribute.value.to_string())
            .unwrap_or_else(|| "unspecified".to_string());

        for scope in resource.scope_metrics {
            for metric in scope.metrics {
                if metric.name != "rpp.runtime.rpc.rate_limit.total" {
                    continue;
                }

                if let Metric::Sum(Sum { data_points, .. }) = metric.data {
                    for point in data_points {
                        let mut class = None;
                        let mut method = None;
                        let mut status = None;
                        let mut tenant = None;
                        for KeyValue { key, value } in point.attributes {
                            match key.as_str() {
                                "class" => class = Some(value.to_string()),
                                "method" => method = Some(value.to_string()),
                                "status" => status = Some(value.to_string()),
                                "tenant" => tenant = Some(value.to_string()),
                                _ => {}
                            }
                        }

                        if let (Some(class), Some(method), Some(status)) = (class, method, status) {
                            counts.insert(
                                (
                                    backend.clone(),
                                    class,
                                    method,
                                    status,
                                    tenant.unwrap_or_else(|| "absent".to_string()),
                                ),
                                point.value,
                            );
                        }
                    }
                }
            }
        }
    }

    counts
}
