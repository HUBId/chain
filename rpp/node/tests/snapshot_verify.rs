use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use assert_cmd::Command as AssertCommand;
use ed25519_dalek::{Signer, SigningKey};
use predicates::str::contains;
use rpp_chain::runtime::config::NodeConfig;
use rpp_node::RuntimeMode;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct SnapshotFixture {
    temp: TempDir,
    config_path: PathBuf,
    chunk_path: PathBuf,
}

impl SnapshotFixture {
    fn new() -> Result<Self> {
        let temp = TempDir::new().context("create temp dir")?;
        let base = temp.path();

        let snapshot_dir = base.join("snapshots");
        let manifest_dir = snapshot_dir.join("manifest");
        let chunk_dir = snapshot_dir.join("chunks");
        fs::create_dir_all(&manifest_dir).context("create manifest dir")?;
        fs::create_dir_all(&chunk_dir).context("create chunk dir")?;

        let chunk_path = chunk_dir.join("chunk-000.bin");
        let chunk_data = b"consistent payload";
        fs::write(&chunk_path, chunk_data).context("write chunk file")?;

        let checksum = sha256_hex(chunk_data);
        let manifest = json!({
            "segments": [{
                "segment_name": "chunk-000.bin",
                "size_bytes": chunk_data.len(),
                "sha256": checksum,
            }],
        });
        let manifest_path = manifest_dir.join("chunks.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).context("encode manifest")?,
        )
        .context("write manifest")?;

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let manifest_bytes = fs::read(&manifest_path).context("read manifest bytes")?;
        let signature = signing_key.sign(&manifest_bytes);
        let signature_path = manifest_dir.join("chunks.json.sig");
        fs::write(&signature_path, hex::encode(signature.to_bytes()))
            .context("write manifest signature")?;

        let key_path = base.join("keys/timetoke_snapshot.toml");
        write_signing_key(&key_path, &signing_key).context("write signing key")?;

        let mut config = NodeConfig::for_mode(RuntimeMode::Validator);
        config.data_dir = base.join("data");
        config.snapshot_dir = snapshot_dir;
        config.timetoke_snapshot_key_path = key_path;
        config.key_path = base.join("keys/node.toml");
        config.p2p_key_path = base.join("keys/p2p.toml");
        config.vrf_key_path = base.join("keys/vrf.toml");
        config.network.rpc.listen = "127.0.0.1:0".parse().context("parse RPC listen addr")?;
        config.network.p2p.peerstore_path = base.join("p2p/peerstore.json");
        config.network.p2p.gossip_path = Some(base.join("p2p/gossip.json"));

        let config_path = base.join("validator.toml");
        config
            .save(&config_path)
            .map_err(|err| anyhow::anyhow!(err))?;

        Ok(SnapshotFixture {
            temp,
            config_path,
            chunk_path,
        })
    }
}

#[test]
fn snapshot_verify_command_succeeds() -> Result<()> {
    let fixture = SnapshotFixture::new()?;

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("verify")
        .arg("--config")
        .arg(&fixture.config_path)
        .assert()
        .success()
        .stdout(contains("\"signature_valid\": true"))
        .stdout(contains("\"checksum_mismatches\": 0"));

    drop(fixture);
    Ok(())
}

#[test]
fn snapshot_verify_command_detects_mismatch() -> Result<()> {
    let fixture = SnapshotFixture::new()?;

    fs::write(&fixture.chunk_path, b"tampered payload").context("corrupt snapshot chunk")?;

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("verify")
        .arg("--config")
        .arg(&fixture.config_path)
        .assert()
        .failure()
        .code(3)
        .stdout(contains("\"checksum_mismatches\": 1"));

    drop(fixture);
    Ok(())
}

fn write_signing_key(path: &Path, signing_key: &SigningKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create key directory")?;
    }
    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let payload = format!("secret_key = \"{secret_hex}\"\npublic_key = \"{public_hex}\"\n");
    fs::write(path, payload).context("write signing key")?;
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
