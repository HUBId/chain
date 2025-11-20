use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use tar::Archive;
use tempfile::TempDir;

use crate::wallet_bundle::{compute_sha256, create_tarball, reproducible_timestamp};
use crate::workspace_root;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FirmwareManifest {
    vendor: String,
    product: String,
    version: String,
    package: String,
    sha256: String,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FirmwareAttestationPayload {
    vendor: String,
    product: String,
    version: String,
    package: String,
    package_sha256: String,
    manifest_sha256: String,
    signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareAttestation {
    payload: FirmwareAttestationPayload,
    public_key: String,
    signature: String,
}

#[derive(Debug, Clone)]
struct FirmwareOptions {
    artifact_dir: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    signing_key: Option<PathBuf>,
    vendors: Vec<String>,
    verify: Vec<PathBuf>,
    help: bool,
}

impl Default for FirmwareOptions {
    fn default() -> Self {
        Self {
            artifact_dir: None,
            output_dir: None,
            signing_key: None,
            vendors: Vec::new(),
            verify: Vec::new(),
            help: false,
        }
    }
}

pub(crate) fn manage_wallet_firmware(args: &[String]) -> Result<()> {
    let mut opts = FirmwareOptions::default();
    parse_args(args, &mut opts)?;

    if opts.help {
        usage();
        return Ok(());
    }

    if !opts.verify.is_empty() {
        for path in opts.verify {
            verify_firmware_bundle(&path)
                .with_context(|| format!("verify firmware bundle {}", path.display()))?;
            println!("verified firmware bundle: {}", path.display());
        }
        return Ok(());
    }

    let workspace = workspace_root();
    let artifact_dir = opts
        .artifact_dir
        .unwrap_or_else(|| workspace.join("rpp/wallet/src/hw/artifacts"));
    let output_root = opts
        .output_dir
        .unwrap_or_else(|| workspace.join("dist/artifacts/firmware"));

    let signing_key = load_signing_key(&workspace, opts.signing_key.as_deref())?;
    let manifests = load_manifests(&artifact_dir, &opts.vendors)?;
    if manifests.is_empty() {
        bail!(
            "no firmware manifests found under {}",
            artifact_dir.display()
        );
    }

    let mut bundles: Vec<PathBuf> = Vec::new();
    for manifest in manifests {
        let path = build_firmware_bundle(&workspace, &output_root, &manifest, &signing_key)
            .with_context(|| {
                format!("build bundle for {} {}", manifest.vendor, manifest.version)
            })?;
        verify_firmware_bundle(&path)?;
        println!("firmware bundle created: {}", path.display());
        bundles.push(path);
    }

    if bundles.is_empty() {
        bail!("firmware build finished without creating bundles");
    }

    Ok(())
}

fn parse_args(args: &[String], opts: &mut FirmwareOptions) -> Result<()> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--artifact-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--artifact-dir requires a value"))?;
                opts.artifact_dir = Some(PathBuf::from(value));
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a path"))?;
                opts.output_dir = Some(PathBuf::from(value));
            }
            "--signing-key" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signing-key requires a path"))?;
                opts.signing_key = Some(PathBuf::from(value));
            }
            "--vendor" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--vendor requires a value"))?;
                opts.vendors.push(value.to_string());
            }
            "--verify" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--verify requires a bundle path"))?;
                opts.verify.push(PathBuf::from(value));
            }
            "--help" | "-h" => opts.help = true,
            other => bail!("unknown argument '{other}' for wallet-firmware"),
        }
    }
    Ok(())
}

fn usage() {
    println!(
        "Usage: cargo xtask wallet-firmware [options]\n\n\
Options:\n  --artifact-dir <dir>   Directory containing firmware manifests (default: rpp/wallet/src/hw/artifacts)\n  --output <dir>         Output directory for signed bundles (default: dist/artifacts/firmware)\n  --signing-key <path>   Base64 or hex-encoded Ed25519 seed used to sign attestations\n  --vendor <name>        Build only manifests that match the given vendor (repeatable)\n  --verify <path>        Verify an existing bundle tarball instead of building (repeatable)\n  -h, --help             Show this help text"
    );
}

fn load_signing_key(workspace: &Path, key_override: Option<&Path>) -> Result<SigningKey> {
    let path = if let Some(path) = key_override {
        path.to_path_buf()
    } else if let Ok(env_path) = std::env::var("WALLET_FIRMWARE_SIGNING_KEY") {
        let trimmed = env_path.trim();
        if trimmed.is_empty() {
            bail!("WALLET_FIRMWARE_SIGNING_KEY is empty");
        }
        PathBuf::from(trimmed)
    } else {
        let fallback = workspace.join("deploy/firmware/test_firmware_signing.key");
        if fallback.exists() {
            fallback
        } else {
            bail!("--signing-key is required unless WALLET_FIRMWARE_SIGNING_KEY or deploy/firmware/test_firmware_signing.key exists");
        }
    };

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read signing key from {}", path.display()))?;
    let trimmed = raw.trim();
    let bytes = BASE64
        .decode(trimmed.as_bytes())
        .or_else(|_| hex::decode(trimmed))
        .with_context(|| format!("decode signing key from {}", path.display()))?;
    if bytes.len() != SECRET_KEY_LENGTH {
        bail!(
            "signing key must be {SECRET_KEY_LENGTH} bytes, found {} from {}",
            bytes.len(),
            path.display()
        );
    }
    let seed: [u8; SECRET_KEY_LENGTH] = bytes
        .try_into()
        .map_err(|_| anyhow!("failed to coerce signing key into fixed array"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_manifests(dir: &Path, vendors: &[String]) -> Result<Vec<FirmwareManifest>> {
    let mut manifests = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("read firmware manifest dir {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read firmware manifest {}", path.display()))?;
        let manifest: FirmwareManifest = serde_json::from_str(&raw)
            .with_context(|| format!("parse firmware manifest {}", path.display()))?;
        if !vendors.is_empty()
            && !vendors
                .iter()
                .any(|vendor| vendor.eq_ignore_ascii_case(&manifest.vendor))
        {
            continue;
        }
        manifests.push(manifest);
    }
    Ok(manifests)
}

fn build_firmware_bundle(
    workspace: &Path,
    output_root: &Path,
    manifest: &FirmwareManifest,
    signing_key: &SigningKey,
) -> Result<PathBuf> {
    let staging = TempDir::new()?;
    let bundle_dir = staging.path().join(bundle_directory_name(
        &manifest.vendor,
        &manifest.product,
        &manifest.version,
    ));
    fs::create_dir_all(&bundle_dir)?;

    let manifest_path = bundle_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .context("write firmware manifest")?;
    let manifest_sha = compute_sha256(&manifest_path)?;

    let package_source = workspace.join(&manifest.package);
    if !package_source.exists() {
        bail!("package {} not found", package_source.display());
    }
    let package_dest = bundle_dir.join(&manifest.package);
    if let Some(parent) = package_dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&package_source, &package_dest)
        .with_context(|| format!("copy package {}", package_source.display()))?;
    let package_sha = compute_sha256(&package_dest)?;
    if package_sha != manifest.sha256 {
        bail!(
            "package digest mismatch for {}: expected {}, found {}",
            manifest.package,
            manifest.sha256,
            package_sha
        );
    }

    let payload = FirmwareAttestationPayload {
        vendor: manifest.vendor.clone(),
        product: manifest.product.clone(),
        version: manifest.version.clone(),
        package: manifest.package.clone(),
        package_sha256: package_sha.clone(),
        manifest_sha256: manifest_sha,
        signed_at: reproducible_timestamp()?,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = signing_key.sign(&payload_bytes);
    let attestation = FirmwareAttestation {
        payload,
        public_key: BASE64.encode(signing_key.verifying_key().as_bytes()),
        signature: BASE64.encode(signature.to_bytes()),
    };
    let attestation_path = bundle_dir.join("attestation.json");
    fs::write(&attestation_path, serde_json::to_vec_pretty(&attestation)?)
        .context("write firmware attestation")?;

    write_checksums(&bundle_dir, manifest, &attestation)?;

    let archive_name = format!(
        "wallet-firmware-{}-{}-{}.tar.gz",
        slugify(&manifest.vendor),
        slugify(&manifest.product),
        slugify(&manifest.version)
    );
    let vendor_dir = output_root.join(slugify(&manifest.vendor));
    fs::create_dir_all(&vendor_dir)?;
    let archive_path = vendor_dir.join(archive_name);
    create_tarball(
        &bundle_dir,
        &archive_path,
        bundle_dir.file_name().unwrap().to_str().unwrap(),
    )?;
    Ok(archive_path)
}

fn write_checksums(
    root: &Path,
    manifest: &FirmwareManifest,
    attestation: &FirmwareAttestation,
) -> Result<()> {
    let path = root.join("SHA256SUMS.txt");
    let mut file = File::create(&path)?;

    let manifest_hash = compute_sha256(&root.join("manifest.json"))?;
    let attestation_hash = compute_sha256(&root.join("attestation.json"))?;
    writeln!(&mut file, "{manifest_hash}  manifest.json")?;
    writeln!(&mut file, "{attestation_hash}  attestation.json")?;
    writeln!(
        &mut file,
        "{}  {}",
        attestation.payload.package_sha256, manifest.package
    )?;
    let checksum_self = compute_sha256(&path)?;
    writeln!(&mut file, "{checksum_self}  SHA256SUMS.txt")?;
    Ok(())
}

fn verify_firmware_bundle(bundle: &Path) -> Result<()> {
    if !bundle.exists() {
        bail!("bundle {} does not exist", bundle.display());
    }
    let staging = TempDir::new()?;
    let file = File::open(bundle)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.unpack(staging.path())?;

    let bundle_root = detect_bundle_root(staging.path())?;
    let manifest_path = bundle_root.join("manifest.json");
    let attestation_path = bundle_root.join("attestation.json");
    if !manifest_path.exists() {
        bail!("manifest.json missing from {}", bundle.display());
    }
    if !attestation_path.exists() {
        bail!("attestation.json missing from {}", bundle.display());
    }

    let manifest: FirmwareManifest =
        serde_json::from_slice(&fs::read(&manifest_path)?).context("parse manifest.json")?;
    let attestation: FirmwareAttestation =
        serde_json::from_slice(&fs::read(&attestation_path)?).context("parse attestation.json")?;

    let manifest_sha = compute_sha256(&manifest_path)?;
    if attestation.payload.manifest_sha256 != manifest_sha {
        bail!(
            "manifest digest mismatch: attested {}, actual {manifest_sha}",
            attestation.payload.manifest_sha256
        );
    }
    if attestation.payload.package != manifest.package
        || attestation.payload.package_sha256 != manifest.sha256
    {
        bail!("attestation does not match manifest package reference");
    }

    let package_path = bundle_root.join(&manifest.package);
    if !package_path.exists() {
        bail!("package {} missing from bundle", manifest.package);
    }
    let package_sha = compute_sha256(&package_path)?;
    if package_sha != manifest.sha256 {
        bail!(
            "package digest mismatch for {}: manifest {}, actual {}",
            manifest.package,
            manifest.sha256,
            package_sha
        );
    }

    let payload_bytes = serde_json::to_vec(&attestation.payload)?;
    let signature_bytes = BASE64
        .decode(attestation.signature.as_bytes())
        .with_context(|| "decode attestation signature")?;
    if signature_bytes.len() != SIGNATURE_LENGTH {
        bail!(
            "signature length mismatch: expected {SIGNATURE_LENGTH}, found {}",
            signature_bytes.len()
        );
    }
    let signature: Signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| anyhow!("failed to coerce signature bytes"))?,
    );
    let public_key_bytes = BASE64
        .decode(attestation.public_key.as_bytes())
        .with_context(|| "decode attestation public key")?;
    if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
        bail!(
            "public key length mismatch: expected {PUBLIC_KEY_LENGTH}, found {}",
            public_key_bytes.len()
        );
    }
    let verifying_key = VerifyingKey::from_bytes(
        &public_key_bytes
            .try_into()
            .map_err(|_| anyhow!("failed to coerce public key bytes"))?,
    )?;
    verifying_key.verify_strict(&payload_bytes, &signature)?;

    Ok(())
}

fn detect_bundle_root(staging: &Path) -> Result<PathBuf> {
    let mut entries: Vec<_> = fs::read_dir(staging)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .collect();
    if entries.is_empty() {
        bail!("bundle archive did not contain a root directory");
    }
    entries.sort_by_key(|entry| entry.path());
    Ok(entries.remove(0).path())
}

fn slugify(input: &str) -> String {
    let mut slug = String::new();
    let mut last_hyphen = false;
    for ch in input.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_hyphen {
                slug.push('-');
                last_hyphen = true;
            }
        } else {
            slug.push(mapped);
            last_hyphen = false;
        }
    }
    slug.trim_matches('-').to_string()
}

fn bundle_directory_name(vendor: &str, product: &str, version: &str) -> String {
    format!(
        "wallet-firmware-{}-{}-{}",
        slugify(vendor),
        slugify(product),
        slugify(version)
    )
}
