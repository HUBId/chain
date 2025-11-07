use std::fs::{self, File};
use std::path::Path;

use anyhow::Result;
use csv::Writer;

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
    writer.write_record(&[
        "chunk_retries".to_string(),
        summary.chunk_retries.to_string(),
    ])?;

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

    writer.write_record(&[
        "mesh_changes".to_string(),
        summary.mesh_changes.len().to_string(),
    ])?;
    writer.write_record(&["fault_events".to_string(), summary.faults.len().to_string()])?;

    if let Some(recovery) = &summary.recovery {
        writer.write_record(&[
            "recovery_resume_events".to_string(),
            recovery.resume_latencies_ms.len().to_string(),
        ])?;
        if let Some(max) = recovery.max_resume_latency_ms {
            writer.write_record(&["recovery_max_resume_ms".to_string(), format!("{:.3}", max)])?;
        }
        if let Some(mean) = recovery.mean_resume_latency_ms {
            writer.write_record(&[
                "recovery_mean_resume_ms".to_string(),
                format!("{:.3}", mean),
            ])?;
        }
    }

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
            chunk_retries: 1,
            propagation: Some(super::super::reduce::PropagationPercentiles {
                p50_ms: 120.0,
                p95_ms: 340.5,
            }),
            mesh_changes: Vec::new(),
            faults: Vec::new(),
            recovery: Some(super::super::reduce::RecoveryMetrics {
                resume_latencies_ms: vec![1500.0],
                max_resume_latency_ms: Some(1500.0),
                mean_resume_latency_ms: Some(1500.0),
            }),
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
