use std::fs;
use std::path::Path;

use anyhow::Result;

use super::reduce::SimulationSummary;

pub fn export_json<P: AsRef<Path>>(path: P, summary: &SimulationSummary) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(summary)?;
    fs::write(path, json)?;
    Ok(())
}
