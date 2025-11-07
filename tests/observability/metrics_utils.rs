use std::net::SocketAddr;

use anyhow::{Context, Result};
use reqwest::Client;

pub async fn fetch_metrics(client: &Client, addr: SocketAddr) -> Result<String> {
    let response = client
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .with_context(|| format!("fetch metrics from {addr}"))?
        .error_for_status()
        .with_context(|| format!("metrics endpoint at {addr} returned error status"))?;
    response
        .text()
        .await
        .with_context(|| format!("decode metrics body from {addr}"))
}

pub fn metric_value(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with(name) {
            return None;
        }

        if !labels
            .iter()
            .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        {
            return None;
        }

        line.split_whitespace()
            .last()
            .and_then(|value| value.parse::<f64>().ok())
    })
}
