use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry_otlp::{self, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::trace::{BatchConfig, BatchConfigBuilder, Sampler};
use reqwest::Client as HttpClient;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use crate::config::TelemetryConfig;

const AUTHORIZATION_HEADER: &str = "Authorization";

pub struct TelemetryExporterBuilder<'a> {
    config: &'a TelemetryConfig,
}

#[derive(Debug)]
pub struct ExporterBuildOutcome<T> {
    pub exporter: Option<T>,
    pub failover_used: bool,
}

impl<'a> TelemetryExporterBuilder<'a> {
    pub fn new(config: &'a TelemetryConfig) -> Self {
        Self { config }
    }

    pub fn grpc_endpoint(&self) -> Option<&str> {
        normalized_endpoint(self.config.endpoint.as_ref())
    }

    pub fn http_endpoint(&self) -> Option<&str> {
        normalized_endpoint(self.config.http_endpoint.as_ref())
            .or_else(|| normalized_endpoint(self.config.endpoint.as_ref()))
    }

    fn secondary_grpc_endpoint(&self) -> Option<&str> {
        normalized_endpoint(self.config.secondary_endpoint.as_ref())
    }

    fn secondary_http_endpoint(&self) -> Option<&str> {
        normalized_endpoint(self.config.secondary_http_endpoint.as_ref())
            .or_else(|| normalized_endpoint(self.config.secondary_endpoint.as_ref()))
    }

    pub fn build_metric_exporter(
        &self,
    ) -> Result<ExporterBuildOutcome<opentelemetry_otlp::MetricExporter>> {
        if !self.config.enabled {
            return Ok(ExporterBuildOutcome {
                exporter: None,
                failover_used: false,
            });
        }
        let Some(endpoint) = self.http_endpoint() else {
            return Ok(ExporterBuildOutcome {
                exporter: None,
                failover_used: false,
            });
        };

        let mut failover_used = false;

        match self.build_metric_exporter_for_endpoint(endpoint) {
            Ok(exporter) => Ok(ExporterBuildOutcome {
                exporter: Some(exporter),
                failover_used,
            }),
            Err(error) if self.config.failover_enabled => {
                failover_used = true;
                let Some(secondary) = self.secondary_http_endpoint() else {
                    return Err(error);
                };
                let exporter = self
                    .build_metric_exporter_for_endpoint(secondary)
                    .context("failed to build OTLP metrics exporter via secondary endpoint")?;
                Ok(ExporterBuildOutcome {
                    exporter: Some(exporter),
                    failover_used,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn build_metric_exporter_for_endpoint(
        &self,
        endpoint: &str,
    ) -> Result<opentelemetry_otlp::MetricExporter> {
        let mut builder = opentelemetry_otlp::MetricExporter::builder().with_http();
        builder = builder.with_endpoint(endpoint.to_string());
        builder = builder.with_timeout(self.timeout());

        if let Some(headers) = self.auth_headers() {
            builder = builder.with_headers(headers);
        }

        if let Some(client) = self.build_http_client()? {
            builder = builder.with_http_client(client);
        }

        builder = builder.with_temporality(Temporality::Cumulative);

        builder
            .build()
            .context("failed to build OTLP metrics exporter")
    }

    pub fn build_span_exporter(
        &self,
    ) -> Result<ExporterBuildOutcome<opentelemetry_otlp::SpanExporter>> {
        if !self.config.enabled {
            return Ok(ExporterBuildOutcome {
                exporter: None,
                failover_used: false,
            });
        }
        let Some(endpoint) = self.grpc_endpoint() else {
            return Ok(ExporterBuildOutcome {
                exporter: None,
                failover_used: false,
            });
        };

        let mut failover_used = false;
        match self.build_span_exporter_for_endpoint(endpoint) {
            Ok(exporter) => Ok(ExporterBuildOutcome {
                exporter: Some(exporter),
                failover_used,
            }),
            Err(error) if self.config.failover_enabled => {
                failover_used = true;
                let Some(secondary) = self.secondary_grpc_endpoint() else {
                    return Err(error);
                };
                let exporter = self
                    .build_span_exporter_for_endpoint(secondary)
                    .context("failed to build OTLP span exporter via secondary endpoint")?;
                Ok(ExporterBuildOutcome {
                    exporter: Some(exporter),
                    failover_used,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn build_span_exporter_for_endpoint(
        &self,
        endpoint: &str,
    ) -> Result<opentelemetry_otlp::SpanExporter> {
        let mut exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint.to_string())
            .with_timeout(self.timeout());

        if let Some(metadata) = self.auth_metadata()? {
            exporter = exporter.with_metadata(metadata);
        }

        if let Some(tls) = self.build_grpc_tls_config(endpoint)? {
            exporter = exporter.with_tls_config(tls);
        }

        exporter
            .build_span_exporter()
            .context("failed to build OTLP span exporter")
    }

    pub fn build_trace_batch_config(&self) -> BatchConfig {
        BatchConfigBuilder::default()
            .with_max_queue_size(self.config.trace_max_queue_size)
            .with_max_export_batch_size(self.config.trace_max_export_batch_size)
            .build()
    }

    pub fn trace_sampler(&self) -> Sampler {
        let ratio = self.config.trace_sample_ratio.clamp(0.0, 1.0);

        if ratio <= 0.0 {
            Sampler::AlwaysOff
        } else if (ratio - 1.0).abs() < f64::EPSILON {
            Sampler::AlwaysOn
        } else {
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio)))
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.timeout_ms.max(1))
    }

    fn auth_headers(&self) -> Option<HashMap<String, String>> {
        self.auth_token().map(|token| {
            let mut headers = HashMap::new();
            headers.insert(AUTHORIZATION_HEADER.to_string(), token);
            headers
        })
    }

    fn auth_metadata(&self) -> Result<Option<MetadataMap>> {
        let Some(token) = self.auth_token() else {
            return Ok(None);
        };

        let mut metadata = MetadataMap::new();
        let value = MetadataValue::from_str(&token).context("invalid telemetry auth token")?;
        metadata.insert("authorization", value);
        Ok(Some(metadata))
    }

    fn auth_token(&self) -> Option<String> {
        self.config
            .auth_token
            .as_ref()
            .map(|token| token.trim())
            .filter(|token| !token.is_empty())
            .map(|token| {
                if token.to_ascii_lowercase().starts_with("bearer ") {
                    token.to_string()
                } else {
                    format!("Bearer {token}")
                }
            })
    }

    fn build_http_client(&self) -> Result<Option<HttpClient>> {
        let Some(tls) = self
            .config
            .http_tls
            .as_ref()
            .or(self.config.grpc_tls.as_ref())
        else {
            return Ok(None);
        };

        let mut builder = HttpClient::builder().timeout(self.timeout());

        if tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ca) = tls.ca_certificate.as_ref() {
            let pem = fs::read(ca).with_context(|| {
                format!("failed to read telemetry CA certificate {}", ca.display())
            })?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .context("failed to parse telemetry CA certificate")?;
            builder = builder.add_root_certificate(certificate);
        }

        if let (Some(cert), Some(key)) = (
            tls.client_certificate.as_ref(),
            tls.client_private_key.as_ref(),
        ) {
            let mut identity_bytes = fs::read(cert).with_context(|| {
                format!(
                    "failed to read telemetry client certificate {}",
                    cert.display()
                )
            })?;
            let key_bytes = fs::read(key).with_context(|| {
                format!("failed to read telemetry client key {}", key.display())
            })?;
            identity_bytes.extend_from_slice(&key_bytes);
            let identity = reqwest::Identity::from_pem(&identity_bytes)
                .context("failed to parse telemetry client identity")?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .context("failed to build telemetry HTTP client")?;
        Ok(Some(client))
    }

    fn build_grpc_tls_config(&self, endpoint: &str) -> Result<Option<ClientTlsConfig>> {
        let Some(tls) = self.config.grpc_tls.as_ref() else {
            return Ok(None);
        };

        let mut config = ClientTlsConfig::new();

        if let Some(domain) = tls
            .domain_name
            .as_ref()
            .and_then(|domain| Some(domain.trim()).filter(|value| !value.is_empty()))
        {
            config = config.domain_name(domain.to_string());
        }

        if let Some(ca) = tls.ca_certificate.as_ref() {
            let pem = fs::read(ca).with_context(|| {
                format!("failed to read telemetry CA certificate {}", ca.display())
            })?;
            config = config.ca_certificate(Certificate::from_pem(pem));
        }

        if let (Some(cert), Some(key)) = (
            tls.client_certificate.as_ref(),
            tls.client_private_key.as_ref(),
        ) {
            let mut identity_bytes = fs::read(cert).with_context(|| {
                format!(
                    "failed to read telemetry client certificate {}",
                    cert.display()
                )
            })?;
            let key_bytes = fs::read(key).with_context(|| {
                format!("failed to read telemetry client key {}", key.display())
            })?;
            identity_bytes.extend_from_slice(&key_bytes);
            config = config.identity(Identity::from_pem(identity_bytes));
        }

        if tls.domain_name.is_none() {
            if let Some(host) = host_from_endpoint(endpoint) {
                config = config.domain_name(host.to_string());
            }
        }

        Ok(Some(config))
    }
}

fn host_from_endpoint(endpoint: &str) -> Option<&str> {
    endpoint
        .parse::<http::Uri>()
        .ok()
        .and_then(|uri| uri.host())
}

fn normalized_endpoint(value: Option<&String>) -> Option<&str> {
    value
        .map(|candidate| candidate.trim())
        .filter(|candidate| !candidate.is_empty())
}
