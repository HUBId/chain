use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ERROR_FRAGMENT: &str = "The Plonky3 backend cannot be combined with the mock prover feature.";

fn cargo_bin() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

fn run_guard_check(features: &str) -> (bool, String) {
    let cargo = cargo_bin();

    let output = Command::new(cargo)
        .current_dir(env!("CARGO_WORKSPACE_DIR"))
        .arg("check")
        .arg("--package")
        .arg("rpp-node")
        .arg("--no-default-features")
        .arg("--features")
        .arg(features)
        .output()
        .expect("failed to execute cargo check for feature guard test");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stderr)
}

#[test]
fn backend_plonky3_rejected_with_mock_prover() {
    let (success, stderr) = run_guard_check("backend-plonky3,prover-mock");
    assert!(
        !success,
        "expected cargo check to fail when backend-plonky3 and prover-mock are combined\n{}",
        stderr
    );
    assert!(
        stderr.contains(ERROR_FRAGMENT),
        "feature guard error message missing from stderr\n{}",
        stderr
    );
}

#[test]
fn backend_plonky3_gpu_rejected_with_mock_prover() {
    let (success, stderr) = run_guard_check("backend-plonky3-gpu,prover-mock");
    assert!(
        !success,
        "expected cargo check to fail when backend-plonky3-gpu and prover-mock are combined\n{}",
        stderr
    );
    assert!(
        stderr.contains(ERROR_FRAGMENT),
        "feature guard error message missing from stderr\n{}",
        stderr
    );
}

#[cfg(not(miri))]
mod wallet_capability_guard_tests {
    use super::cargo_bin;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use tempfile::{tempdir, TempDir};

    const WALLET_BASE_FEATURES: &str = "runtime,prover-mock,backup";
    const WALLET_CHAIN_BASE_FEATURES: &str = "runtime-cli,wallet-integration";

    struct WalletConfigFixture {
        #[allow(dead_code)]
        temp_dir: TempDir,
        config_path: PathBuf,
    }

    impl WalletConfigFixture {
        fn new(extra_sections: impl FnOnce(&Path) -> String) -> Self {
            let temp_dir = tempdir().expect("create wallet config tempdir");
            let config_path = write_wallet_config(temp_dir.path(), extra_sections(temp_dir.path()));
            Self {
                temp_dir,
                config_path,
            }
        }

        fn path(&self) -> &Path {
            &self.config_path
        }
    }

    fn write_wallet_config(root: &Path, extra_sections: String) -> PathBuf {
        let data_dir = root.join("data");
        let keys_dir = root.join("keys");
        let engine_dir = root.join("engine");
        let backup_dir = engine_dir.join("backups");
        let key_path = keys_dir.join("wallet.toml");
        let keystore_path = engine_dir.join("keystore.toml");

        for dir in [&data_dir, &keys_dir, &engine_dir, &backup_dir] {
            fs::create_dir_all(dir).expect("create wallet config directory");
        }

        let mut config = format!(
            r#"
data_dir = "{data_dir}"

[wallet.rpc]
listen = "127.0.0.1:0"

[wallet.keys]
key_path = "{key_path}"

[wallet.engine]
data_dir = "{engine_dir}"
keystore_path = "{keystore_path}"
backup_path = "{backup_dir}"

[wallet.policy]
external_gap_limit = 20
internal_gap_limit = 20
min_confirmations = 1
dust_limit = 546
max_change_outputs = 1
pending_lock_timeout = 600

[wallet.fees]
default_sats_per_vbyte = 5
min_sats_per_vbyte = 1
max_sats_per_vbyte = 200

[wallet.prover]
backend = "mock"
require_proof = false
allow_broadcast_without_proof = false
timeout_secs = 300
max_witness_bytes = 16777216
max_concurrency = 1

[wallet.budgets]
submit_transaction_per_minute = 120
proof_generation_per_minute = 60
pipeline_depth = 64

[wallet.rescan]
auto_trigger = false
lookback_blocks = 2880
chunk_size = 64

[node]
embedded = false
gossip_endpoints = ["/ip4/127.0.0.1/tcp/7600"]
"#,
            data_dir = data_dir.display(),
            key_path = key_path.display(),
            engine_dir = engine_dir.display(),
            keystore_path = keystore_path.display(),
            backup_dir = backup_dir.display()
        );

        let trimmed = extra_sections.trim();
        if !trimmed.is_empty() {
            config.push_str("\n");
            config.push_str(trimmed);
            config.push_str("\n");
        }

        let config_path = root.join("wallet-config.toml");
        fs::write(&config_path, config).expect("write wallet config");
        config_path
    }

    fn run_wallet_command(features: &str, config_path: &Path) -> Output {
        Command::new(cargo_bin())
            .current_dir(env!("CARGO_WORKSPACE_DIR"))
            .arg("run")
            .arg("--package")
            .arg("rpp-wallet")
            .arg("--no-default-features")
            .arg("--features")
            .arg(features)
            .arg("--")
            .arg("--dry-run")
            .arg("--wallet-config")
            .arg(config_path)
            .output()
            .expect("run rpp-wallet")
    }

    fn run_chain_wallet_command(features: &str, config_path: &Path) -> Output {
        Command::new(cargo_bin())
            .current_dir(env!("CARGO_WORKSPACE_DIR"))
            .arg("run")
            .arg("--package")
            .arg("rpp-chain")
            .arg("--no-default-features")
            .arg("--features")
            .arg(features)
            .arg("--")
            .arg("wallet")
            .arg("--dry-run")
            .arg("--wallet-config")
            .arg(config_path)
            .output()
            .expect("run rpp-chain wallet guard")
    }

    fn multisig_section(_: &Path) -> String {
        "[wallet.multisig]\nenabled = true\n".to_owned()
    }

    fn zsi_section(_: &Path) -> String {
        "[wallet.zsi]\nenabled = true\nbackend = \"mock\"\n".to_owned()
    }

    fn hardware_section(_: &Path) -> String {
        "[wallet.hw]\nenabled = true\ntransport = \"hid\"\n".to_owned()
    }

    fn wallet_security_section(root: &Path) -> String {
        let cert_dir = root.join("certs");
        fs::create_dir_all(&cert_dir).expect("create cert directory");
        let server_cert = cert_dir.join("server.crt");
        let server_key = cert_dir.join("server.key");
        let ca_cert = cert_dir.join("ca.crt");
        for path in [&server_cert, &server_key, &ca_cert] {
            fs::write(path, b"placeholder").expect("write certificate placeholder");
        }

        format!(
            r#"[wallet.security]
mtls_enabled = true

[wallet.rpc.security]
certificate = "{cert}"
private_key = "{key}"
ca_certificate = "{ca}"
"#,
            cert = server_cert.display(),
            key = server_key.display(),
            ca = ca_cert.display()
        )
    }

    fn wallet_error_output(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("stdout:\n{stdout}\nstderr:\n{stderr}")
    }

    #[test]
    fn wallet_multisig_guard_rejects_without_feature() {
        let fixture = WalletConfigFixture::new(multisig_section);
        let output = run_wallet_command(WALLET_BASE_FEATURES, fixture.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "wallet binary should fail without multisig feature\n{}",
            wallet_error_output(&output)
        );
        assert!(
            stderr.contains("wallet multisig support disabled at build time"),
            "missing multisig guard error in stderr\n{}",
            stderr
        );
    }

    #[test]
    fn wallet_multisig_guard_allows_with_feature() {
        let fixture = WalletConfigFixture::new(multisig_section);
        let output = run_wallet_command(
            "runtime,prover-mock,backup,wallet_multisig_hooks",
            fixture.path(),
        );
        assert!(
            output.status.success(),
            "wallet binary should accept multisig config when feature enabled\n{}",
            wallet_error_output(&output)
        );
    }

    #[test]
    fn wallet_zsi_guard_rejects_without_feature() {
        let fixture = WalletConfigFixture::new(zsi_section);
        let output = run_wallet_command(WALLET_BASE_FEATURES, fixture.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "wallet binary should fail without zsi feature\n{}",
            wallet_error_output(&output)
        );
        assert!(
            stderr.contains("zsi workflows disabled by configuration"),
            "missing zsi guard error in stderr\n{}",
            stderr
        );
    }

    #[test]
    fn wallet_zsi_guard_allows_with_feature() {
        let fixture = WalletConfigFixture::new(zsi_section);
        let output = run_wallet_command("runtime,prover-mock,backup,wallet_zsi", fixture.path());
        assert!(
            output.status.success(),
            "wallet binary should accept zsi config when feature enabled\n{}",
            wallet_error_output(&output)
        );
    }

    #[test]
    fn wallet_hardware_guard_rejects_without_feature() {
        let fixture = WalletConfigFixture::new(hardware_section);
        let output = run_wallet_command(WALLET_BASE_FEATURES, fixture.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "wallet binary should fail without hardware feature\n{}",
            wallet_error_output(&output)
        );
        assert!(
            stderr.contains("wallet hardware support disabled at build time"),
            "missing hardware guard error in stderr\n{}",
            stderr
        );
    }

    #[test]
    fn wallet_hardware_guard_allows_with_feature() {
        let fixture = WalletConfigFixture::new(hardware_section);
        let output = run_wallet_command("runtime,prover-mock,backup,wallet_hw", fixture.path());
        assert!(
            output.status.success(),
            "wallet binary should accept hardware config when feature enabled\n{}",
            wallet_error_output(&output)
        );
    }

    #[test]
    fn wallet_rpc_security_guard_rejects_without_feature() {
        let fixture = WalletConfigFixture::new(wallet_security_section);
        let output = run_wallet_command(WALLET_BASE_FEATURES, fixture.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "wallet binary should fail without wallet_rpc_mtls feature\n{}",
            wallet_error_output(&output)
        );
        assert!(
            stderr.contains("wallet security"),
            "missing wallet_rpc_mtls guard in stderr\n{}",
            stderr
        );
    }

    #[test]
    fn wallet_rpc_security_guard_allows_with_feature() {
        let fixture = WalletConfigFixture::new(wallet_security_section);
        let output =
            run_wallet_command("runtime,prover-mock,backup,wallet_rpc_mtls", fixture.path());
        assert!(
            output.status.success(),
            "wallet binary should accept wallet security config when feature enabled\n{}",
            wallet_error_output(&output)
        );
    }

    #[test]
    fn chain_wallet_rpc_security_guard_rejects_without_feature() {
        let fixture = WalletConfigFixture::new(wallet_security_section);
        let output = run_chain_wallet_command(WALLET_CHAIN_BASE_FEATURES, fixture.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "chain CLI should fail wallet security validation without wallet_rpc_mtls\n{}",
            wallet_error_output(&output)
        );
        assert!(
            stderr.contains("wallet.rpc.security"),
            "missing chain wallet_rpc_mtls guard in stderr\n{}",
            stderr
        );
    }

    #[test]
    fn chain_wallet_rpc_security_guard_allows_with_feature() {
        let fixture = WalletConfigFixture::new(wallet_security_section);
        let output = run_chain_wallet_command(
            "runtime-cli,wallet-integration,wallet_rpc_mtls",
            fixture.path(),
        );
        assert!(
            output.status.success(),
            "chain CLI should accept wallet security config when wallet_rpc_mtls enabled\n{}",
            wallet_error_output(&output)
        );
    }
}
