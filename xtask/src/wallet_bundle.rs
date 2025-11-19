use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tar::{Builder as TarBuilder, HeaderMode};
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use toml::Value as TomlValue;

use crate::{run_command, workspace_root};

#[derive(Debug, Clone)]
struct FeatureConfig {
    disable_defaults: bool,
    features: Vec<String>,
}

impl FeatureConfig {
    fn new(disable_defaults: bool, features: Vec<String>) -> Self {
        Self {
            disable_defaults,
            features,
        }
    }
}

#[derive(Debug)]
struct WalletBundleConfig {
    target: Option<String>,
    profile: String,
    profile_overridden: bool,
    version: Option<String>,
    tool: String,
    output: PathBuf,
    cli_features: FeatureConfig,
    gui_features: FeatureConfig,
    configs: Vec<PathBuf>,
    help: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WalletBuildContext {
    pub workspace: PathBuf,
    pub output_root: PathBuf,
    pub target: String,
    pub profile: String,
    pub version: String,
    pub cli_features: Vec<String>,
    pub gui_features: Vec<String>,
    pub cli_binary: PathBuf,
    pub gui_binary: PathBuf,
    pub config_paths: Vec<PathBuf>,
}

impl Default for WalletBundleConfig {
    fn default() -> Self {
        Self {
            target: None,
            profile: "release".to_string(),
            profile_overridden: false,
            version: None,
            tool: "cargo".to_string(),
            output: PathBuf::from("dist/artifacts"),
            cli_features: FeatureConfig::new(
                true,
                vec![
                    "runtime".to_string(),
                    "prover-mock".to_string(),
                    "backup".to_string(),
                ],
            ),
            gui_features: FeatureConfig::new(
                true,
                vec![
                    "runtime".to_string(),
                    "wallet_gui".to_string(),
                    "prover-mock".to_string(),
                    "backup".to_string(),
                ],
            ),
            configs: Vec::new(),
            help: false,
        }
    }
}

#[derive(Debug, Serialize)]
struct WalletBundleManifest {
    version: String,
    target: String,
    profile: String,
    generated_at: String,
    cli_features: Vec<String>,
    gui_features: Vec<String>,
    files: Vec<WalletBundleFile>,
}

#[derive(Debug, Serialize)]
struct WalletBundleFile {
    path: String,
    sha256: String,
    size: u64,
}

struct ChecksumEntry {
    path: String,
    sha256: String,
}

pub(crate) fn prepare_wallet_build(args: &[String]) -> Result<Option<WalletBuildContext>> {
    let mut config = WalletBundleConfig::default();
    parse_wallet_bundle_args(args, &mut config)?;
    if config.help {
        wallet_bundle_usage();
        return Ok(None);
    }

    let workspace = workspace_root();
    let repro = ReproSettings::detect(&workspace)?;
    if repro.enabled && !config.profile_overridden {
        config.profile = "repro".to_string();
    }

    let target = config
        .target
        .as_ref()
        .ok_or_else(|| anyhow!("--target is required"))?;
    let version = config
        .version
        .as_ref()
        .ok_or_else(|| anyhow!("--version is required"))?;

    let output_root = if config.output.is_absolute() {
        config.output.clone()
    } else {
        workspace.join(&config.output)
    };

    let wallet_toolchain = wallet_toolchain_channel(&workspace)?;

    let cli_features = normalize_features(&config.cli_features.features);
    let gui_features = normalize_features(&config.gui_features.features);

    enforce_feature_policy(&cli_features, "CLI")?;
    enforce_feature_policy(&gui_features, "GUI")?;

    let cli_binary = build_binary(
        &workspace,
        &config.tool,
        "rpp-wallet",
        "rpp-wallet",
        target,
        &config.profile,
        config.cli_features.disable_defaults,
        &cli_features,
        wallet_toolchain.as_deref(),
        &repro,
    )?;

    let gui_binary = build_binary(
        &workspace,
        &config.tool,
        "rpp-wallet-lib",
        "rpp-wallet-gui",
        target,
        &config.profile,
        config.gui_features.disable_defaults,
        &gui_features,
        wallet_toolchain.as_deref(),
        &repro,
    )?;

    let config_paths = resolve_config_paths(&workspace, &config.configs)?;

    Ok(Some(WalletBuildContext {
        workspace,
        output_root,
        target: target.clone(),
        profile: config.profile.clone(),
        version: version.clone(),
        cli_features,
        gui_features,
        cli_binary,
        gui_binary,
        config_paths,
    }))
}

pub(crate) fn build_wallet_bundle(args: &[String]) -> Result<()> {
    let Some(context) = prepare_wallet_build(args)? else {
        return Ok(());
    };

    let bundle_name = format!("wallet-bundle-{}-{}", context.version, context.target);
    let staging_dir = TempDir::new()?;
    let bundle_root = staging_dir.path().join(&bundle_name);
    fs::create_dir_all(bundle_root.join("bin"))?;
    fs::create_dir_all(bundle_root.join("config"))?;
    fs::create_dir_all(bundle_root.join("manifests"))?;
    fs::create_dir_all(bundle_root.join("docs"))?;
    fs::create_dir_all(bundle_root.join("hooks"))?;
    fs::create_dir_all(bundle_root.join("systemd"))?;

    let mut manifest_files: Vec<WalletBundleFile> = Vec::new();
    let mut checksums: Vec<ChecksumEntry> = Vec::new();

    copy_binary(&context.cli_binary, &bundle_root.join("bin/rpp-wallet"))?;
    add_entry(
        &bundle_root,
        "bin/rpp-wallet",
        Some(&mut manifest_files),
        &mut checksums,
    )?;

    copy_binary(&context.gui_binary, &bundle_root.join("bin/rpp-wallet-gui"))?;
    add_entry(
        &bundle_root,
        "bin/rpp-wallet-gui",
        Some(&mut manifest_files),
        &mut checksums,
    )?;

    for path in &context.config_paths {
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("config path {} is missing a filename", path.display()))?;
        let dest = bundle_root.join("config").join(file_name);
        fs::copy(path, &dest).with_context(|| format!("copy config {}", path.display()))?;
        add_entry(
            &bundle_root,
            &format!("config/{}", file_name.to_string_lossy()),
            Some(&mut manifest_files),
            &mut checksums,
        )?;
    }

    let version_file = bundle_root.join("VERSION");
    fs::write(&version_file, format!("{}\n", context.version))
        .context("write bundle VERSION file")?;
    add_entry(&bundle_root, "VERSION", None, &mut checksums)?;

    copy_shared_docs(
        &context.workspace,
        &bundle_root,
        &mut manifest_files,
        &mut checksums,
    )?;
    copy_platform_hooks(
        &context.workspace,
        &context.target,
        &bundle_root,
        &mut manifest_files,
        &mut checksums,
    )?;

    let manifest = WalletBundleManifest {
        version: context.version.clone(),
        target: context.target.clone(),
        profile: context.profile.clone(),
        generated_at: reproducible_timestamp()?,
        cli_features: context.cli_features.clone(),
        gui_features: context.gui_features.clone(),
        files: manifest_files,
    };

    let manifest_path = bundle_root.join("manifests/wallet-bundle-manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .context("write wallet bundle manifest")?;
    add_entry(
        &bundle_root,
        "manifests/wallet-bundle-manifest.json",
        None,
        &mut checksums,
    )?;

    write_checksums(&bundle_root, &checksums)?;

    let tarball_name = format!("{bundle_name}.tar.gz");
    let target_dir = context.output_root.join("wallet").join(&context.target);
    fs::create_dir_all(&target_dir)?;
    let tarball_path = target_dir.join(&tarball_name);
    create_tarball(&bundle_root, &tarball_path, &bundle_name)?;

    let manifest_output = target_dir.join(format!("{bundle_name}-manifest.json"));
    fs::copy(&manifest_path, &manifest_output)
        .with_context(|| format!("copy manifest to {}", manifest_output.display()))?;

    println!(
        "wallet bundle created: {} (manifest: {})",
        tarball_path.display(),
        manifest_output.display()
    );

    Ok(())
}

fn parse_wallet_bundle_args(args: &[String], config: &mut WalletBundleConfig) -> Result<()> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--target requires a value"))?;
                config.target = Some(value.to_string());
            }
            "--profile" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--profile requires a value"))?;
                config.profile = value.to_string();
                config.profile_overridden = true;
            }
            "--version" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--version requires a value"))?;
                config.version = Some(value.to_string());
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                config.output = PathBuf::from(value);
            }
            "--tool" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--tool requires a value"))?;
                if value != "cargo" && value != "cross" {
                    bail!("--tool must be either 'cargo' or 'cross'");
                }
                config.tool = value.to_string();
            }
            "--cli-features" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--cli-features requires a value"))?;
                config.cli_features.features = parse_feature_list(value);
            }
            "--gui-features" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--gui-features requires a value"))?;
                config.gui_features.features = parse_feature_list(value);
            }
            "--cli-allow-defaults" => {
                config.cli_features.disable_defaults = false;
            }
            "--gui-allow-defaults" => {
                config.gui_features.disable_defaults = false;
            }
            "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--config requires a path"))?;
                config.configs.push(PathBuf::from(value));
            }
            "--help" | "-h" => {
                config.help = true;
            }
            other => bail!("unknown argument '{other}' for wallet-bundle"),
        }
    }
    if config.configs.is_empty() {
        config.configs.push(PathBuf::from("config/wallet.toml"));
    }
    Ok(())
}

fn wallet_bundle_usage() {
    println!(
        "Usage: cargo xtask wallet-bundle --target <triple> --version <semver> [options]\n\n\
Options:\n  --target <triple>        Target triple to compile for\n  --version <semver>       Version string encoded in the bundle name\n  --profile <name>         Cargo profile to use (default: release)\n  --output <dir>           Directory to write artifacts (default: dist/artifacts)\n  --tool <cargo|cross>     Build tool to invoke (default: cargo)\n  --cli-features <list>    Comma/space separated feature list for the CLI binary\n                           (default: runtime,prover-stwo)\n  --gui-features <list>    Comma/space separated feature list for the GUI binary\n                           (default: wallet_gui,prover-stwo)\n  --cli-allow-defaults     Do not add --no-default-features for the CLI build\n  --gui-allow-defaults     Do not add --no-default-features for the GUI build\n  --config <path>          Include the specified config file (repeatable)\n  --help                   Show this help text\n"
    );
}

fn parse_feature_list(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter_map(|segment| {
            let trimmed = segment.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

fn normalize_features(features: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for feature in features {
        let trimmed = feature.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_string());
        }
    }
    set.into_iter().collect()
}

fn enforce_feature_policy(features: &[String], label: &str) -> Result<()> {
    for feature in features {
        let canonical = feature.replace('_', "-");
        match canonical.as_str() {
            "prover-mock" => {
                bail!("{label} feature list cannot include prover-mock for reproducible releases");
            }
            "backend-plonky3" | "backend-plonky3-gpu" => {
                bail!("{label} feature list cannot include experimental backend-plonky3 variants");
            }
            _ => {}
        }
    }
    Ok(())
}

fn build_binary(
    workspace: &Path,
    tool: &str,
    package: &str,
    binary: &str,
    target: &str,
    profile: &str,
    disable_defaults: bool,
    features: &[String],
    toolchain: Option<&str>,
    repro: &ReproSettings,
) -> Result<PathBuf> {
    let mut command = Command::new(tool);
    command.current_dir(workspace);
    if let Some(channel) = toolchain {
        command.arg(format!("+{channel}"));
    }
    command
        .arg("build")
        .arg("--locked")
        .arg("--package")
        .arg(package)
        .arg("--bin")
        .arg(binary)
        .arg("--profile")
        .arg(profile)
        .arg("--target")
        .arg(target);
    if disable_defaults {
        command.arg("--no-default-features");
    }
    if !features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }
    repro.apply(&mut command);
    let context = format!("build {package}/{binary} for {target} ({profile})");
    run_command(command, &context)?;

    let file_name = binary_name(binary, target);
    let path = workspace
        .join("target")
        .join(target)
        .join(profile)
        .join(&file_name);
    if !path.exists() {
        bail!("expected binary {} to exist after build", path.display());
    }
    Ok(path)
}

pub(crate) fn binary_name(binary: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("{binary}.exe")
    } else {
        binary.to_string()
    }
}

#[derive(Debug, Clone)]
struct ReproSettings {
    enabled: bool,
    remap_flag: Option<String>,
    source_date_epoch: Option<String>,
}

impl ReproSettings {
    fn detect(workspace: &Path) -> Result<Self> {
        let enabled = repro_mode_enabled();
        let source_date_epoch = if enabled {
            Some(ensure_source_date_epoch_value(workspace)?)
        } else {
            env::var("SOURCE_DATE_EPOCH")
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        let remap_flag = if enabled {
            Some(format!(
                "--remap-path-prefix={}=/repro/workspace",
                workspace.display()
            ))
        } else {
            None
        };
        Ok(Self {
            enabled,
            remap_flag,
            source_date_epoch,
        })
    }

    fn apply(&self, command: &mut Command) {
        if self.enabled {
            command.env("REPRO_MODE", "1");
        }
        if let Some(epoch) = &self.source_date_epoch {
            command.env("SOURCE_DATE_EPOCH", epoch);
        }
        if let Some(flag) = &self.remap_flag {
            command.env("RUSTFLAGS", merge_rustflags(flag));
        }
    }
}

fn repro_mode_enabled() -> bool {
    matches!(
        env::var("REPRO_MODE")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase()),
        Some(mode) if !mode.is_empty() && mode != "0"
    )
}

fn ensure_source_date_epoch_value(workspace: &Path) -> Result<String> {
    if let Ok(value) = env::var("SOURCE_DATE_EPOCH") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let output = Command::new("git")
        .current_dir(workspace)
        .arg("log")
        .arg("-1")
        .arg("--format=%ct")
        .output()
        .context("capture SOURCE_DATE_EPOCH from git")?;
    if !output.status.success() {
        bail!("git log exited with status {}", output.status);
    }
    let epoch = String::from_utf8(output.stdout)?.trim().to_string();
    env::set_var("SOURCE_DATE_EPOCH", &epoch);
    Ok(epoch)
}

fn merge_rustflags(flag: &str) -> String {
    let current = env::var("RUSTFLAGS").unwrap_or_default();
    if current.split_whitespace().any(|existing| existing == flag) {
        return current;
    }
    if current.trim().is_empty() {
        flag.to_string()
    } else {
        format!("{current} {flag}")
    }
}

fn wallet_toolchain_channel(workspace: &Path) -> Result<Option<String>> {
    if let Ok(value) = env::var("CHAIN_WALLET_TOOLCHAIN") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    let file = workspace.join("rust-toolchain.wallet.toml");
    if !file.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&file).context("read rust-toolchain.wallet.toml")?;
    let parsed: TomlValue = toml::from_str(&raw).context("parse rust-toolchain.wallet.toml")?;
    let channel = parsed
        .get("toolchain")
        .and_then(|toolchain| toolchain.get("channel"))
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string());
    Ok(channel)
}

fn reproducible_timestamp() -> Result<String> {
    if let Ok(epoch) = env::var("SOURCE_DATE_EPOCH") {
        let trimmed = epoch.trim();
        if !trimmed.is_empty() {
            let seconds: i64 = trimmed.parse()?;
            let time = OffsetDateTime::from_unix_timestamp(seconds)?;
            return Ok(time.format(&Rfc3339)?);
        }
    }
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

pub(crate) fn copy_binary(source: &Path, dest: &Path) -> Result<()> {
    fs::copy(source, dest).with_context(|| format!("copy binary from {}", source.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dest, perms)?;
    }
    Ok(())
}

fn resolve_config_paths(workspace: &Path, configs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::new();
    for config in configs {
        let absolute = if config.is_absolute() {
            config.clone()
        } else {
            workspace.join(config)
        };
        if !absolute.exists() {
            bail!("config file {} not found", absolute.display());
        }
        resolved.push(absolute);
    }
    Ok(resolved)
}

fn add_entry(
    root: &Path,
    relative: &str,
    manifest_files: Option<&mut Vec<WalletBundleFile>>,
    checksums: &mut Vec<ChecksumEntry>,
) -> Result<()> {
    let path = root.join(relative);
    if !path.exists() {
        bail!("bundle file {} missing", path.display());
    }
    let sha = compute_sha256(&path)?;
    if let Some(files) = manifest_files {
        let size = fs::metadata(&path)?.len();
        files.push(WalletBundleFile {
            path: relative.to_string(),
            sha256: sha.clone(),
            size,
        });
    }
    checksums.push(ChecksumEntry {
        path: relative.to_string(),
        sha256: sha,
    });
    Ok(())
}

fn copy_shared_docs(
    workspace: &Path,
    bundle_root: &Path,
    manifest_files: &mut Vec<WalletBundleFile>,
    checksums: &mut Vec<ChecksumEntry>,
) -> Result<()> {
    let docs = [
        ("LICENSE.md", "docs/LICENSE.md"),
        ("README.md", "docs/README.md"),
        ("INSTALL.wallet.md", "docs/INSTALL.md"),
    ];
    for (source, dest) in docs {
        let source_path = workspace.join(source);
        if !source_path.exists() {
            bail!("wallet doc {} missing", source_path.display());
        }
        let dest_path = bundle_root.join(dest);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&source_path, &dest_path)
            .with_context(|| format!("copy wallet doc {}", source_path.display()))?;
        add_entry(bundle_root, dest, Some(manifest_files), checksums)?;
    }
    Ok(())
}

fn copy_platform_hooks(
    workspace: &Path,
    target: &str,
    bundle_root: &Path,
    manifest_files: &mut Vec<WalletBundleFile>,
    checksums: &mut Vec<ChecksumEntry>,
) -> Result<()> {
    if target.contains("linux") {
        copy_template_file(
            workspace.join("deploy/systemd/rpp-wallet-rpc.service"),
            bundle_root,
            "systemd/rpp-wallet-rpc.service",
            Some(manifest_files),
            checksums,
        )?;
        copy_template_file(
            workspace.join("deploy/install/linux/postinstall.sh"),
            bundle_root,
            "hooks/postinstall.sh",
            Some(manifest_files),
            checksums,
        )?;
        copy_template_file(
            workspace.join("deploy/install/linux/prerm.sh"),
            bundle_root,
            "hooks/prerm.sh",
            Some(manifest_files),
            checksums,
        )?;
    } else if target.contains("windows") {
        copy_template_file(
            workspace.join("deploy/install/windows/install.ps1"),
            bundle_root,
            "hooks/install.ps1",
            Some(manifest_files),
            checksums,
        )?;
        copy_template_file(
            workspace.join("deploy/install/windows/uninstall.ps1"),
            bundle_root,
            "hooks/uninstall.ps1",
            Some(manifest_files),
            checksums,
        )?;
    } else if target.contains("apple-darwin") || target.contains("macos") {
        copy_template_file(
            workspace.join("deploy/install/macos/postinstall.sh"),
            bundle_root,
            "hooks/postinstall.sh",
            Some(manifest_files),
            checksums,
        )?;
        copy_template_file(
            workspace.join("deploy/install/macos/uninstall.sh"),
            bundle_root,
            "hooks/uninstall.sh",
            Some(manifest_files),
            checksums,
        )?;
    }
    Ok(())
}

fn copy_template_file(
    source: PathBuf,
    bundle_root: &Path,
    dest_relative: &str,
    manifest_files: Option<&mut Vec<WalletBundleFile>>,
    checksums: &mut Vec<ChecksumEntry>,
) -> Result<()> {
    if !source.exists() {
        bail!("wallet template {} missing", source.display());
    }
    let dest = bundle_root.join(dest_relative);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&source, &dest)
        .with_context(|| format!("copy wallet template {}", source.display()))?;
    add_entry(bundle_root, dest_relative, manifest_files, checksums)?;
    Ok(())
}

fn write_checksums(root: &Path, entries: &[ChecksumEntry]) -> Result<()> {
    let path = root.join("SHA256SUMS.txt");
    let mut file = File::create(&path)?;
    for entry in entries {
        writeln!(
            &mut file,
            "{}  {}",
            entry.sha256,
            entry.path.replace('\\', "/")
        )?;
    }
    // include the checksum file itself last
    let sha = compute_sha256(&path)?;
    let mut file = OpenOptions::new().append(true).open(&path)?;
    writeln!(&mut file, "{}  SHA256SUMS.txt", sha)?;
    Ok(())
}

pub(crate) fn create_tarball(source_dir: &Path, output: &Path, bundle_name: &str) -> Result<()> {
    let file = File::create(output)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = TarBuilder::new(encoder);
    builder.mode(HeaderMode::Deterministic);
    builder.append_dir_all(bundle_name, source_dir)?;
    builder.into_inner()?.finish()?;
    Ok(())
}

pub(crate) fn compute_sha256(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open file for checksum {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read file for checksum {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
