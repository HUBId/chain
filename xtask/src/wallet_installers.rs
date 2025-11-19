use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use tempfile::TempDir;
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::run_command;
use crate::wallet_bundle::{
    binary_name, compute_sha256, copy_binary, create_tarball, prepare_wallet_build,
    WalletBuildContext,
};

pub(crate) fn build_wallet_installers(args: &[String]) -> Result<()> {
    let mut signing_tool: Option<String> = None;
    let mut signing_args: Vec<String> = Vec::new();
    let mut bundle_identifier: Option<String> = None;
    let mut passthrough: Vec<String> = Vec::new();
    let mut help = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--signing-tool" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signing-tool requires a path"))?;
                signing_tool = Some(value.to_string());
            }
            "--signing-arg" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signing-arg requires a value"))?;
                signing_args.push(value.to_string());
            }
            "--bundle-identifier" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--bundle-identifier requires a value"))?;
                bundle_identifier = Some(value.to_string());
            }
            "--help" | "-h" => {
                help = true;
            }
            other => passthrough.push(other.to_string()),
        }
    }

    if help {
        wallet_installer_usage();
        return Ok(());
    }

    let Some(context) = prepare_wallet_build(&passthrough)? else {
        return Ok(());
    };
    let platform = detect_platform(&context.target)?;
    let options = InstallerOptions {
        signing_tool,
        signing_args,
        bundle_identifier,
    };

    match platform {
        InstallerPlatform::Linux => build_linux_installers(&context)?,
        InstallerPlatform::Windows => build_windows_installers(&context, &options)?,
        InstallerPlatform::MacOs => build_macos_installers(&context, &options)?,
    }

    Ok(())
}

fn wallet_installer_usage() {
    println!(
        "Usage: cargo xtask wallet-installer [wallet bundle args] [options]\n\n\
Options:\n  --signing-tool <path>    Optional signtool executable used to sign .msi installers\n  --signing-arg <value>    Extra arguments forwarded to the signing tool (repeatable)\n  --bundle-identifier <id> Bundle identifier override for macOS pkgbuild\n  -h, --help               Show this help text\n\nAll other arguments are forwarded to wallet-bundle so the binaries, features, and\nconfigs stay consistent across the bundle and installer flows."
    );
}

#[derive(Debug, Clone)]
struct InstallerOptions {
    signing_tool: Option<String>,
    signing_args: Vec<String>,
    bundle_identifier: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallerPlatform {
    Linux,
    Windows,
    MacOs,
}

fn detect_platform(target: &str) -> Result<InstallerPlatform> {
    if target.contains("windows") {
        Ok(InstallerPlatform::Windows)
    } else if target.contains("apple-darwin") {
        Ok(InstallerPlatform::MacOs)
    } else if target.contains("linux") {
        Ok(InstallerPlatform::Linux)
    } else {
        bail!("wallet installers are not supported for target {target}");
    }
}

fn build_linux_installers(ctx: &WalletBuildContext) -> Result<()> {
    let (os_label, arch_label) = canonical_labels(&ctx.target)?;
    let feature_tag = canonical_feature_tag(ctx);
    let base_name = format!(
        "rpp-wallet-{}-{}-{}-{}",
        ctx.version, os_label, arch_label, feature_tag
    );
    let output_dir = artifact_output_dir(ctx)?;

    let staging = TempDir::new()?;
    let payload_root = staging.path().join(&base_name);
    stage_common_payload(ctx, &payload_root, InstallerPlatform::Linux)?;

    let tarball_path = output_dir.join(format!("{base_name}.tar.gz"));
    create_tarball(&payload_root, &tarball_path, &base_name)?;
    finalize_artifact(&tarball_path)?;

    let deb_path = run_cargo_deb(ctx, &output_dir, &base_name)?;
    finalize_artifact(&deb_path)?;
    let rpm_path = run_cargo_rpm(ctx, &output_dir, &base_name)?;
    finalize_artifact(&rpm_path)?;

    Ok(())
}

fn build_windows_installers(ctx: &WalletBuildContext, options: &InstallerOptions) -> Result<()> {
    let (os_label, arch_label) = canonical_labels(&ctx.target)?;
    let feature_tag = canonical_feature_tag(ctx);
    let base_name = format!(
        "rpp-wallet-{}-{}-{}-{}",
        ctx.version, os_label, arch_label, feature_tag
    );
    let output_dir = artifact_output_dir(ctx)?;

    let staging = TempDir::new()?;
    let payload_root = staging.path().join(&base_name);
    stage_common_payload(ctx, &payload_root, InstallerPlatform::Windows)?;

    let zip_path = output_dir.join(format!("{base_name}.zip"));
    create_zip_archive(&payload_root, &zip_path)?;
    finalize_artifact(&zip_path)?;

    let msi_path = run_cargo_wix(ctx, &output_dir, &base_name)?;
    if let Some(tool) = &options.signing_tool {
        sign_windows_installer(tool, &options.signing_args, &msi_path)?;
    }
    finalize_artifact(&msi_path)?;

    Ok(())
}

fn build_macos_installers(ctx: &WalletBuildContext, options: &InstallerOptions) -> Result<()> {
    let (os_label, arch_label) = canonical_labels(&ctx.target)?;
    let feature_tag = canonical_feature_tag(ctx);
    let base_name = format!(
        "rpp-wallet-{}-{}-{}-{}",
        ctx.version, os_label, arch_label, feature_tag
    );
    let output_dir = artifact_output_dir(ctx)?;

    let app_bundle = build_macos_app(ctx)?;
    embed_docs_into_app(ctx, &app_bundle)?;

    let pkg_path = output_dir.join(format!("{base_name}.pkg"));
    run_pkgbuild(&app_bundle, options, &pkg_path)?;
    finalize_artifact(&pkg_path)?;

    let dmg_path = output_dir.join(format!("{base_name}.dmg"));
    run_hdiutil(&app_bundle, &dmg_path)?;
    finalize_artifact(&dmg_path)?;

    Ok(())
}

fn artifact_output_dir(ctx: &WalletBuildContext) -> Result<PathBuf> {
    let dir = ctx.output_root.join("wallet").join(&ctx.target);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn canonical_labels(target: &str) -> Result<(&'static str, String)> {
    let os_label = if target.contains("windows") {
        "windows"
    } else if target.contains("apple-darwin") {
        "macos"
    } else if target.contains("linux") {
        "linux"
    } else {
        bail!("unsupported wallet installer target {target}");
    };
    let arch = target.split('-').next().unwrap_or(target);
    let arch_label = if arch == "aarch64" && os_label == "macos" {
        "arm64".to_string()
    } else {
        arch.to_string()
    };
    Ok((os_label, arch_label))
}

fn canonical_feature_tag(ctx: &WalletBuildContext) -> String {
    let mut set = BTreeSet::new();
    for feature in ctx.cli_features.iter().chain(ctx.gui_features.iter()) {
        let canonical = feature.trim().replace('_', "-");
        if canonical.is_empty() {
            continue;
        }
        set.insert(canonical);
    }
    if set.is_empty() {
        "default".to_string()
    } else {
        set.into_iter().collect::<Vec<_>>().join("+")
    }
}

fn stage_common_payload(
    ctx: &WalletBuildContext,
    root: &Path,
    platform: InstallerPlatform,
) -> Result<()> {
    fs::create_dir_all(root.join("bin"))?;
    fs::create_dir_all(root.join("config"))?;
    fs::create_dir_all(root.join("docs"))?;
    fs::create_dir_all(root.join("hooks"))?;
    fs::create_dir_all(root.join("systemd"))?;

    let cli_name = binary_name("rpp-wallet", &ctx.target);
    let gui_name = binary_name("rpp-wallet-gui", &ctx.target);
    copy_binary(&ctx.cli_binary, &root.join("bin").join(cli_name))?;
    copy_binary(&ctx.gui_binary, &root.join("bin").join(gui_name))?;

    for path in &ctx.config_paths {
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("config path {} missing filename", path.display()))?;
        copy_file(path, &root.join("config").join(file_name), Some(0o640))?;
    }

    let mut docs = vec![
        (
            ctx.workspace.join("LICENSE.md"),
            root.join("docs/LICENSE.md"),
            Some(0o644),
        ),
        (
            ctx.workspace.join("README.md"),
            root.join("docs/README.md"),
            Some(0o644),
        ),
        (
            ctx.workspace.join("INSTALL.wallet.md"),
            root.join("docs/INSTALL.md"),
            Some(0o644),
        ),
    ];
    let os_slug = match platform {
        InstallerPlatform::Linux => Some("linux"),
        InstallerPlatform::Windows => Some("windows"),
        InstallerPlatform::MacOs => Some("macos"),
    };
    if let Some(slug) = os_slug {
        docs.push((
            ctx.workspace.join(format!("README-{}.md", slug)),
            root.join(format!("docs/README-{}.md", slug)),
            Some(0o644),
        ));
    }
    for (source, dest, mode) in docs {
        copy_file(&source, &dest, mode)?;
    }

    match platform {
        InstallerPlatform::Linux => {
            copy_file(
                &ctx.workspace.join("deploy/systemd/rpp-wallet-rpc.service"),
                &root.join("systemd/rpp-wallet-rpc.service"),
                Some(0o644),
            )?;
            copy_file(
                &ctx.workspace.join("deploy/install/linux/postinstall.sh"),
                &root.join("hooks/postinstall.sh"),
                Some(0o755),
            )?;
            copy_file(
                &ctx.workspace.join("deploy/install/linux/prerm.sh"),
                &root.join("hooks/prerm.sh"),
                Some(0o755),
            )?;
        }
        InstallerPlatform::Windows => {
            copy_file(
                &ctx.workspace.join("deploy/install/windows/install.ps1"),
                &root.join("hooks/install.ps1"),
                None,
            )?;
            copy_file(
                &ctx.workspace.join("deploy/install/windows/uninstall.ps1"),
                &root.join("hooks/uninstall.ps1"),
                None,
            )?;
        }
        InstallerPlatform::MacOs => {
            copy_file(
                &ctx.workspace.join("deploy/install/macos/postinstall.sh"),
                &root.join("hooks/postinstall.sh"),
                Some(0o755),
            )?;
            copy_file(
                &ctx.workspace.join("deploy/install/macos/uninstall.sh"),
                &root.join("hooks/uninstall.sh"),
                Some(0o755),
            )?;
        }
    }

    fs::write(root.join("VERSION"), format!("{}\n", ctx.version))?;

    Ok(())
}

fn copy_file(source: &Path, dest: &Path, mode: Option<u32>) -> Result<()> {
    if !source.exists() {
        bail!("wallet installer asset {} missing", source.display());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, dest)
        .with_context(|| format!("copy wallet installer asset {}", source.display()))?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(dest, perms)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

fn create_zip_archive(root: &Path, output: &Path) -> Result<()> {
    let file = File::create(output)?;
    let mut writer = ZipWriter::new(file);
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
    let base = root
        .parent()
        .ok_or_else(|| anyhow!("zip payload missing parent directory"))?;

    for entry in WalkDir::new(root) {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(base)?;
        let mut name = relative.to_string_lossy().replace('\\', "/");
        if entry.file_type().is_dir() {
            if !name.ends_with('/') {
                name.push('/');
            }
            writer.add_directory(name, options)?;
        } else {
            writer.start_file(name, options)?;
            let mut input = File::open(path)?;
            std::io::copy(&mut input, &mut writer)?;
        }
    }

    writer.finish()?;
    Ok(())
}

fn run_cargo_deb(ctx: &WalletBuildContext, output_dir: &Path, base_name: &str) -> Result<PathBuf> {
    let mut command = Command::new("cargo");
    command.current_dir(&ctx.workspace);
    command
        .arg("deb")
        .arg("--locked")
        .arg("--package")
        .arg("rpp-wallet")
        .arg("--target")
        .arg(&ctx.target)
        .arg("--no-build");
    if ctx.profile != "release" {
        command.arg("--profile").arg(&ctx.profile);
    }
    run_command(command, "cargo deb rpp-wallet")?;

    let source = find_latest_artifact(&ctx.workspace.join("target"), "deb", "rpp-wallet")?;
    let dest = output_dir.join(format!("{base_name}.deb"));
    fs::copy(&source, &dest)
        .with_context(|| format!("copy deb artifact from {}", source.display()))?;
    Ok(dest)
}

fn run_cargo_rpm(ctx: &WalletBuildContext, output_dir: &Path, base_name: &str) -> Result<PathBuf> {
    let mut command = Command::new("cargo");
    command.current_dir(&ctx.workspace);
    command
        .arg("rpm")
        .arg("build")
        .arg("--target")
        .arg(&ctx.target);
    if ctx.profile != "release" {
        command.arg("--profile").arg(&ctx.profile);
    }
    run_command(command, "cargo rpm build rpp-wallet")?;

    let source = find_latest_artifact(&ctx.workspace.join("target"), "rpm", "rpp-wallet")?;
    let dest = output_dir.join(format!("{base_name}.rpm"));
    fs::copy(&source, &dest)
        .with_context(|| format!("copy rpm artifact from {}", source.display()))?;
    Ok(dest)
}

fn run_cargo_wix(ctx: &WalletBuildContext, output_dir: &Path, base_name: &str) -> Result<PathBuf> {
    let mut command = Command::new("cargo");
    command.current_dir(&ctx.workspace);
    command
        .arg("wix")
        .arg("--nocapture")
        .arg("--package")
        .arg("rpp-wallet")
        .arg("--target")
        .arg(&ctx.target);
    if ctx.profile != "release" {
        command.arg("--profile").arg(&ctx.profile);
    }
    run_command(command, "cargo wix rpp-wallet")?;

    let source = find_latest_artifact(&ctx.workspace.join("target"), "msi", "rpp-wallet")?;
    let dest = output_dir.join(format!("{base_name}.msi"));
    fs::copy(&source, &dest)
        .with_context(|| format!("copy msi artifact from {}", source.display()))?;
    Ok(dest)
}

fn run_pkgbuild(app_bundle: &Path, options: &InstallerOptions, pkg_path: &Path) -> Result<()> {
    let identifier = options
        .bundle_identifier
        .as_deref()
        .unwrap_or("com.rpp.wallet");
    let mut command = Command::new("pkgbuild");
    command
        .arg("--component")
        .arg(app_bundle)
        .arg("--install-location")
        .arg("/Applications")
        .arg("--identifier")
        .arg(identifier)
        .arg(pkg_path);
    run_command(command, "pkgbuild rpp-wallet-gui")
}

fn run_hdiutil(app_bundle: &Path, dmg_path: &Path) -> Result<()> {
    let parent = app_bundle
        .parent()
        .ok_or_else(|| anyhow!("app bundle {} missing parent", app_bundle.display()))?;
    let mut command = Command::new("hdiutil");
    command
        .arg("create")
        .arg(dmg_path)
        .arg("-fs")
        .arg("HFS+")
        .arg("-volname")
        .arg("RPP Wallet")
        .arg("-srcfolder")
        .arg(parent);
    run_command(command, "hdiutil create rpp-wallet dmg")
}

fn build_macos_app(ctx: &WalletBuildContext) -> Result<PathBuf> {
    let manifest = ctx.workspace.join("rpp/wallet/Cargo.toml");
    let mut command = Command::new("cargo");
    command.current_dir(&ctx.workspace);
    command
        .arg("bundle")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--bin")
        .arg("rpp-wallet-gui")
        .arg("--target")
        .arg(&ctx.target);
    if ctx.profile != "release" {
        command.arg("--profile").arg(&ctx.profile);
    }
    run_command(command, "cargo bundle rpp-wallet-gui")?;

    let app_path = ctx
        .workspace
        .join("rpp/wallet")
        .join("target")
        .join(&ctx.target)
        .join(&ctx.profile)
        .join("bundle")
        .join("macos")
        .join("rpp-wallet-gui.app");
    if !app_path.exists() {
        bail!("wallet GUI app bundle {} missing", app_path.display());
    }
    Ok(app_path)
}

fn embed_docs_into_app(ctx: &WalletBuildContext, app_bundle: &Path) -> Result<()> {
    let resources = app_bundle.join("Contents/Resources/docs");
    fs::create_dir_all(&resources)?;
    let docs = [
        (
            ctx.workspace.join("LICENSE.md"),
            resources.join("LICENSE.md"),
        ),
        (ctx.workspace.join("README.md"), resources.join("README.md")),
        (
            ctx.workspace.join("INSTALL.wallet.md"),
            resources.join("INSTALL.md"),
        ),
        (
            ctx.workspace.join("README-macos.md"),
            resources.join("README-macos.md"),
        ),
    ];
    for (source, dest) in docs {
        copy_file(&source, &dest, Some(0o644))?;
    }
    let hooks = resources.join("hooks");
    fs::create_dir_all(&hooks)?;
    copy_file(
        &ctx.workspace.join("deploy/install/macos/postinstall.sh"),
        &hooks.join("postinstall.sh"),
        Some(0o755),
    )?;
    copy_file(
        &ctx.workspace.join("deploy/install/macos/uninstall.sh"),
        &hooks.join("uninstall.sh"),
        Some(0o755),
    )?;
    Ok(())
}

fn sign_windows_installer(tool: &str, args: &[String], artifact: &Path) -> Result<()> {
    let mut command = Command::new(tool);
    if args.is_empty() {
        command.arg("sign");
    } else {
        command.args(args);
    }
    command.arg(artifact);
    run_command(command, "sign wallet installer")
}

fn find_latest_artifact(root: &Path, extension: &str, needle: &str) -> Result<PathBuf> {
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case(extension))
            .unwrap_or(false)
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains(needle))
                .unwrap_or(false)
        {
            let metadata = fs::metadata(path)?;
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            match &newest {
                Some((current, _)) if *current >= modified => {}
                _ => newest = Some((modified, path.to_path_buf())),
            }
        }
    }
    newest
        .map(|(_, path)| path)
        .ok_or_else(|| anyhow!("no {extension} artifacts found under {}", root.display()))
}

fn write_artifact_checksum(path: &Path) -> Result<PathBuf> {
    let sha = compute_sha256(path)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("artifact {} missing filename", path.display()))?
        .to_string_lossy()
        .into_owned();
    let checksum_path = path.with_file_name(format!("{file_name}.sha256"));
    let mut file = File::create(&checksum_path)?;
    writeln!(&mut file, "{sha}  {file_name}")?;
    println!(
        "wallet installer artifact: {} (sha256: {})",
        path.display(),
        sha
    );
    Ok(checksum_path)
}

fn finalize_artifact(path: &Path) -> Result<()> {
    write_artifact_checksum(path).map(|_| ())
}
