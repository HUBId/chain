use std::fs::{self, File};
use std::path::Path;

use anyhow::Result;
use csv::Writer;

use crate::scenario::NodeRole;

use super::reduce::SimulationSummary;

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

pub fn export_json<P: AsRef<Path>>(path: P, summary: &SimulationSummary) -> Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;
    let json = serde_json::to_string_pretty(summary)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn export_csv<P: AsRef<Path>>(path: P, summary: &SimulationSummary) -> Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;

    let file = File::create(path)?;
    let mut writer = Writer::from_writer(file);

    writer.write_record(["metric", "value"])?;
    writer.write_record(&[
        "total_publishes".to_string(),
        summary.total_publishes.to_string(),
    ])?;
    writer.write_record(&[
        "total_receives".to_string(),
        summary.total_receives.to_string(),
    ])?;
    writer.write_record(&["duplicates".to_string(), summary.duplicates.to_string()])?;

    if let Some(propagation) = &summary.propagation {
        writer.write_record(&[
            "propagation_p50_ms".to_string(),
            format!("{:.3}", propagation.p50_ms),
        ])?;
        writer.write_record(&[
            "propagation_p95_ms".to_string(),
            format!("{:.3}", propagation.p95_ms),
        ])?;
    }

    if let Some(reputation) = &summary.reputation_drift {
        writer.write_record(&[
            "reputation_mean_receives".to_string(),
            format!("{:.3}", reputation.mean_receives),
        ])?;
        writer.write_record(&[
            "reputation_std_dev_receives".to_string(),
            format!("{:.3}", reputation.std_dev_receives),
        ])?;
        writer.write_record(&[
            "reputation_max_receives".to_string(),
            reputation.max_receives.to_string(),
        ])?;
        writer.write_record(&[
            "reputation_min_receives".to_string(),
            reputation.min_receives.to_string(),
        ])?;
    }

    if let Some(tier) = &summary.tier_drift {
        writer.write_record(&[
            "tier_expected_per_bucket".to_string(),
            format!("{:.3}", tier.expected_per_tier),
        ])?;
        for bucket in &tier.buckets {
            writer.write_record(&[
                format!("tier_{}_count", bucket.tier),
                bucket.count.to_string(),
            ])?;
            writer.write_record(&[
                format!("tier_{}_avg_receives", bucket.tier),
                format!("{:.3}", bucket.average_receives),
            ])?;
        }
    }

    if let Some(bft) = &summary.bft_success {
        writer.write_record(&["bft_rounds".to_string(), bft.rounds.to_string()])?;
        writer.write_record(&["bft_quorum".to_string(), bft.quorum.to_string()])?;
        writer.write_record(&["bft_successes".to_string(), bft.successes.to_string()])?;
        writer.write_record(&[
            "bft_success_rate".to_string(),
            format!("{:.3}", bft.success_rate),
        ])?;
    }

    if let Some(proof) = &summary.proof_latency {
        writer.write_record(&[
            "proof_latency_p50_ms".to_string(),
            format!("{:.3}", proof.p50_ms),
        ])?;
        writer.write_record(&[
            "proof_latency_p95_ms".to_string(),
            format!("{:.3}", proof.p95_ms),
        ])?;
        writer.write_record(&[
            "proof_latency_p99_ms".to_string(),
            format!("{:.3}", proof.p99_ms),
        ])?;
        writer.write_record(&[
            "proof_latency_max_ms".to_string(),
            format!("{:.3}", proof.max_ms),
        ])?;
    }

    if let Some(perf) = &summary.performance {
        writer.write_record(&[
            "perf_duration_secs".to_string(),
            format!("{:.3}", perf.duration_secs),
        ])?;
        writer.write_record(&[
            "perf_publish_rate_per_sec".to_string(),
            format!("{:.3}", perf.publish_rate_per_sec),
        ])?;
        writer.write_record(&[
            "perf_receive_rate_per_sec".to_string(),
            format!("{:.3}", perf.receive_rate_per_sec),
        ])?;
        writer.write_record(&[
            "perf_duplicate_rate".to_string(),
            format!("{:.4}", perf.duplicate_rate),
        ])?;
        if let Some(mean_latency) = perf.mean_proof_latency_ms {
            writer.write_record(&[
                "perf_mean_proof_latency_ms".to_string(),
                format!("{:.3}", mean_latency),
            ])?;
        }
    }

    if !summary.node_performance.is_empty() {
        let mut validators = 0usize;
        let mut wallets = 0usize;
        for node in &summary.node_performance {
            match node.role {
                NodeRole::Validator => validators += 1,
                NodeRole::Wallet => wallets += 1,
            }
        }
        writer.write_record(&["node_role_validators".to_string(), validators.to_string()])?;
        writer.write_record(&["node_role_wallets".to_string(), wallets.to_string()])?;
    }

    writer.write_record(&[
        "mesh_changes".to_string(),
        summary.mesh_changes.len().to_string(),
    ])?;
    writer.write_record(&["fault_events".to_string(), summary.faults.len().to_string()])?;

    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::SystemTime;

    fn temp_path(extension: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rpp-sim-export-{nanos}.{extension}"))
    }

    fn sample_summary() -> SimulationSummary {
        SimulationSummary {
            total_publishes: 10,
            total_receives: 20,
            duplicates: 3,
            propagation: Some(super::super::reduce::PropagationPercentiles {
                p50_ms: 120.0,
                p95_ms: 340.5,
            }),
            mesh_changes: Vec::new(),
            faults: Vec::new(),
            reputation_drift: None,
            tier_drift: None,
            bft_success: None,
            proof_latency: None,
            performance: None,
            node_performance: Vec::new(),
            comparison: None,
        }
    }

    #[test]
    fn writes_json_summary() {
        let path = temp_path("json");
        let summary = sample_summary();
        export_json(&path, &summary).expect("json export succeeds");
        let written: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("json readable")).unwrap();
        assert_eq!(written, json!(summary));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn writes_csv_summary() {
        let path = temp_path("csv");
        let summary = sample_summary();
        export_csv(&path, &summary).expect("csv export succeeds");
        let content = fs::read_to_string(&path).expect("csv readable");
        assert!(content.contains("metric,value"));
        assert!(content.contains("propagation_p95_ms,340.500"));
        let _ = fs::remove_file(path);
    }
}
