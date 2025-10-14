use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
};

use serde::Serialize;
use storage_firewood::{
    kv::{FirewoodKv, KvError},
    pruning::FirewoodPruner,
    state::FirewoodState,
    wal::WalError,
};
use tempfile::TempDir;

#[derive(Debug, Serialize)]
struct RecoveryReport {
    wal_corruption_detected: bool,
    pruning_proof_verified: bool,
    restored_root: String,
    expected_state_root: String,
    commitment_root: String,
    restored_matches_expected: bool,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_report_path() -> PathBuf {
    let mut args = env::args().skip(1);
    let mut report_path = PathBuf::from("firewood_recovery_report.json");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--report" | "--output" => {
                if let Some(path) = args.next() {
                    report_path = PathBuf::from(path);
                } else {
                    eprintln!("missing value for {arg}");
                }
            }
            other => {
                eprintln!("unrecognized argument: {other}");
            }
        }
    }

    report_path
}

fn main() -> Result<(), Box<dyn Error>> {
    let report_path = parse_report_path();

    println!("🔥 Starting Firewood recovery drill");

    let workspace = TempDir::new()?;
    let data_dir = workspace.path().join("data");
    let snapshot_dir = workspace.path().join("snapshot");
    let restore_dir = workspace.path().join("restore");

    fs::create_dir(&data_dir)?;
    fs::create_dir(&snapshot_dir)?;
    fs::create_dir(&restore_dir)?;

    println!("📦 Preparing baseline state in {:?}", data_dir);
    let state = FirewoodState::open(data_dir.to_str().expect("utf8 path"))?;
    state.put(b"alpha".to_vec(), b"1".to_vec());
    state.put(b"beta".to_vec(), b"2".to_vec());

    let (expected_root, proof) = state.commit_block(1)?;
    let pruning_verified = FirewoodPruner::verify_pruned_state(proof.commitment_root, &proof);
    println!(
        "✅ Recorded block root {} with commitment {} (proof verified: {pruning_verified})",
        to_hex(&expected_root),
        to_hex(&proof.commitment_root)
    );

    let wal_path = data_dir.join("firewood.wal");
    fs::copy(&wal_path, snapshot_dir.join("firewood.wal"))?;
    drop(state);

    println!("⚠️  Corrupting WAL at {:?}", wal_path);
    let metadata = fs::metadata(&wal_path)?;
    let truncated_len = metadata.len().saturating_sub(1);
    let file = OpenOptions::new().write(true).open(&wal_path)?;
    file.set_len(truncated_len)?;

    let wal_corruption_detected = matches!(
        FirewoodKv::open(&data_dir),
        Err(KvError::Wal(WalError::Corrupt))
    );
    println!(
        "{} WAL corruption detected by FileWal::open",
        if wal_corruption_detected {
            "✅"
        } else {
            "❌"
        }
    );

    println!(
        "🧪 Restoring snapshot into {:?} and replaying history",
        restore_dir
    );
    fs::copy(
        snapshot_dir.join("firewood.wal"),
        restore_dir.join("firewood.wal"),
    )?;
    let restored_kv = FirewoodKv::open(&restore_dir)?;
    let restored_root = restored_kv.root_hash();
    let restored_matches_expected = restored_root == expected_root;
    println!(
        "{} Restored root {} matches snapshot",
        if restored_matches_expected {
            "✅"
        } else {
            "❌"
        },
        to_hex(&restored_root)
    );

    let report = RecoveryReport {
        wal_corruption_detected,
        pruning_proof_verified: pruning_verified,
        restored_root: to_hex(&restored_root),
        expected_state_root: to_hex(&expected_root),
        commitment_root: to_hex(&proof.commitment_root),
        restored_matches_expected,
    };

    if let Some(parent) = report_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = File::create(&report_path)?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    file.write_all(b"\n")?;

    println!(
        "📄 Recovery drill report written to {}",
        report_path.display()
    );

    Ok(())
}
