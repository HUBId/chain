use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use blake3::hash as blake3_hash;
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in workspace root")
        .to_path_buf()
}

fn apply_feature_flags(command: &mut Command) {
    let no_defaults = env::var("XTASK_NO_DEFAULT_FEATURES")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if no_defaults {
        command.arg("--no-default-features");
    }
    if let Ok(features) = env::var("XTASK_FEATURES") {
        let trimmed = features.trim();
        if !trimmed.is_empty() {
            command.arg("--features").arg(trimmed);
        }
    }
}

fn run_command(mut command: Command, context: &str) -> Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        bail!("{context} exited with status {status}");
    }
}

fn run_pruning_validation() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("pruning_validation");
    apply_feature_flags(&mut command);
    run_command(command, "pruning validation")
}

fn run_unit_suites() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("unit");
    apply_feature_flags(&mut command);
    run_command(command, "unit test suite")
}

fn run_integration_workflows() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("integration");
    apply_feature_flags(&mut command);
    run_command(command, "integration workflows")
}

fn run_simnet_smoke() -> Result<()> {
    let scenarios = [
        "tools/simnet/scenarios/ci_block_pipeline.ron",
        "tools/simnet/scenarios/ci_state_sync_guard.ron",
        "tools/simnet/scenarios/consensus_quorum_stress.ron",
    ];
    for scenario in scenarios {
        let scenario_path = workspace_root().join(scenario);
        let stem = Path::new(scenario)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("ci-simnet");
        let artifacts = workspace_root()
            .join("target/simnet")
            .join(stem.replace('_', "-"));
        let mut command = Command::new("cargo");
        command
            .current_dir(workspace_root())
            .arg("run")
            .arg("--quiet")
            .arg("--package")
            .arg("simnet")
            .arg("--")
            .arg("--scenario")
            .arg(scenario_path)
            .arg("--artifacts-dir")
            .arg(artifacts);
        apply_feature_flags(&mut command);
        let context = format!("simnet scenario {stem}");
        run_command(command, &context)?;
    }
    Ok(())
}

fn run_consensus_manipulation_tests() -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("--locked")
        .arg("--test")
        .arg("consensus_certificate_tampering");
    apply_feature_flags(&mut command);
    run_command(command, "consensus manipulation checks")
}

fn run_full_test_matrix() -> Result<()> {
    run_unit_suites()?;
    run_integration_workflows()?;
    run_simnet_smoke()
}

fn usage() {
    eprintln!(
        "xtask commands:\n  pruning-validation    Run pruning receipt conformance checks\n  test-unit            Execute lightweight unit test suites\n  test-integration     Execute integration workflows\n  test-simnet          Run the CI simnet scenarios\n  test-consensus-manipulation  Exercise consensus tamper detection tests\n  test-all             Run unit, integration, and simnet scenarios\n  proof-metadata       Export circuit/proof metadata as JSON or markdown\n  plonky3-setup        Regenerate Plonky3 setup JSON descriptors",
    );
}

fn proof_metadata_usage() {
    eprintln!(
        "usage: cargo xtask proof-metadata [--format json|markdown] [--output <path>]\n\nOutputs proof metadata aggregated from Plonky3 setup files, STWO verifying keys, and the blueprint.",
    );
}

fn main() -> Result<()> {
    let mut argv: Vec<String> = env::args().collect();
    let _ = argv.remove(0);
    if argv.is_empty() {
        usage();
        return Ok(());
    }
    let command = argv.remove(0);
    match command.as_str() {
        "pruning-validation" => run_pruning_validation(),
        "test-unit" => run_unit_suites(),
        "test-integration" => run_integration_workflows(),
        "test-simnet" => run_simnet_smoke(),
        "test-consensus-manipulation" => run_consensus_manipulation_tests(),
        "test-all" => run_full_test_matrix(),
        "proof-metadata" => generate_proof_metadata(&argv),
        "plonky3-setup" => regenerate_plonky3_setup(&argv),
        "help" => {
            usage();
            Ok(())
        }
        other => bail!("unknown xtask command: {other}"),
    }
}

fn regenerate_plonky3_setup(args: &[String]) -> Result<()> {
    let root = workspace_root();
    let mut generator: Option<String> = None;
    let mut generator_cwd: Option<PathBuf> = None;
    let mut artifact_dir: Option<PathBuf> = None;
    let mut circuits: Vec<String> = Vec::new();
    let mut toolchain_version = env::var("PLONKY3_TOOLCHAIN_VERSION").ok();
    let mut git_shas: Vec<String> = env_var_list("PLONKY3_GIT_SHAS");
    let mut signature = env::var("PLONKY3_SIGNATURE")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut signature_file = env::var("PLONKY3_SIGNATURE_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let mut signature_output: Option<PathBuf> =
        Some(root.join("config/plonky3/setup/manifest.json"));
    let mut pretty = true;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--generator" => {
                generator = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("--generator requires a value"))?
                        .to_string(),
                );
            }
            "--generator-cwd" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--generator-cwd requires a value"))?;
                generator_cwd = Some(PathBuf::from(value));
            }
            "--artifact-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--artifact-dir requires a value"))?;
                artifact_dir = Some(PathBuf::from(value));
            }
            "--circuits" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--circuits requires a value"))?;
                circuits.extend(
                    value
                        .split(|ch| ch == ',' || ch.is_whitespace())
                        .filter(|segment| !segment.trim().is_empty())
                        .map(|segment| segment.trim().to_string()),
                );
            }
            "--toolchain-version" => {
                toolchain_version = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("--toolchain-version requires a value"))?
                        .to_string(),
                );
            }
            "--git-sha" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--git-sha requires a value"))?;
                git_shas.push(value.to_string());
            }
            "--signature" => {
                signature = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("--signature requires a value"))?
                        .to_string(),
                );
                signature_file = None;
            }
            "--signature-file" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signature-file requires a value"))?;
                signature_file = Some(PathBuf::from(value));
                signature = None;
            }
            "--signature-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--signature-output requires a value"))?;
                signature_output = Some(PathBuf::from(value));
            }
            "--no-signature-output" => {
                signature_output = None;
            }
            "--no-pretty" => {
                pretty = false;
            }
            other => {
                bail!("unknown argument '{other}' for plonky3-setup");
            }
        }
    }

    if signature.is_some() && signature_file.is_some() {
        bail!("--signature and --signature-file cannot be combined");
    }

    let mut fixture_dir: Option<TempDir> = None;
    if generator.is_none() && artifact_dir.is_none() {
        let (dir_handle, path) = materialise_fixture_artifacts(&circuits)?;
        artifact_dir = Some(path);
        fixture_dir = Some(dir_handle);
    }

    let mut command = Command::new("python3");
    command
        .current_dir(&root)
        .arg(root.join("scripts/generate_plonky3_artifacts.py"))
        .arg(root.join("config/plonky3/setup"));

    if !circuits.is_empty() {
        command.arg("--circuits");
        for circuit in &circuits {
            command.arg(circuit);
        }
    }

    if let Some(gen) = generator {
        command.arg("--generator").arg(gen);
    }

    if let Some(cwd) = generator_cwd {
        command.arg("--generator-cwd").arg(cwd);
    }

    if let Some(dir) = artifact_dir {
        command.arg("--artifact-dir").arg(dir);
    }

    if pretty {
        command.arg("--pretty");
    }

    if let Some(version) = toolchain_version.filter(|value| !value.trim().is_empty()) {
        command.arg("--toolchain-version").arg(version);
    }

    for entry in git_shas {
        if !entry.trim().is_empty() {
            command.arg("--git-sha").arg(entry);
        }
    }

    if let Some(sig) = signature.filter(|value| !value.trim().is_empty()) {
        command.arg("--signature").arg(sig);
    }

    if let Some(sig_file) = signature_file {
        command.arg("--signature-file").arg(sig_file);
    }

    if let Some(sig_out) = signature_output {
        command.arg("--signature-output").arg(sig_out);
    }

    run_command(command, "generate Plonky3 setup artifacts")?;
    drop(fixture_dir);
    Ok(())
}

fn env_var_list(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
                .filter(|segment| !segment.trim().is_empty())
                .map(|segment| segment.trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn materialise_fixture_artifacts(circuits: &[String]) -> Result<(TempDir, PathBuf)> {
    let root = workspace_root();
    let setup_dir = root.join("config/plonky3/setup");
    let selected: Option<HashSet<String>> = if circuits.is_empty() {
        None
    } else {
        Some(circuits.iter().cloned().collect())
    };

    let temp_dir = tempfile::tempdir().context("create temporary Plonky3 artifact directory")?;
    let mut generated: HashSet<String> = HashSet::new();

    for entry in
        fs::read_dir(&setup_dir).with_context(|| format!("read {}", setup_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("read Plonky3 setup file {}", path.display()))?;
        let doc: Plonky3ArtifactDoc = serde_json::from_str(&contents)
            .with_context(|| format!("parse Plonky3 setup file {}", path.display()))?;
        if let Some(selection) = &selected {
            if !selection.contains(&doc.circuit) {
                continue;
            }
        }
        let verifying = load_plonky3_artifact(&setup_dir, &doc.verifying_key)?;
        let proving = load_plonky3_artifact(&setup_dir, &doc.proving_key)?;
        fs::write(
            temp_dir.path().join(format!("{}.vk", doc.circuit)),
            verifying,
        )
        .with_context(|| format!("write verifying key for {}", doc.circuit))?;
        fs::write(temp_dir.path().join(format!("{}.pk", doc.circuit)), proving)
            .with_context(|| format!("write proving key for {}", doc.circuit))?;
        generated.insert(doc.circuit);
    }

    if let Some(selection) = &selected {
        let missing: Vec<String> = selection.difference(&generated).cloned().collect();
        if !missing.is_empty() {
            bail!("no fixture data found for circuits: {}", missing.join(", "));
        }
    }

    Ok((temp_dir, temp_dir.path().to_path_buf()))
}

fn generate_proof_metadata(args: &[String]) -> Result<()> {
    let mut format = MetadataFormat::Json;
    let mut output: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--format requires a value"))?;
                format = match value.as_str() {
                    "json" => MetadataFormat::Json,
                    "markdown" | "md" => MetadataFormat::Markdown,
                    other => bail!("unsupported format '{other}'"),
                };
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--output requires a value"))?;
                output = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                proof_metadata_usage();
                return Ok(());
            }
            other => bail!("unknown argument '{other}' for proof-metadata"),
        }
    }

    let report = collect_proof_metadata()?;
    let payload = match format {
        MetadataFormat::Json => serde_json::to_string_pretty(&report)?,
        MetadataFormat::Markdown => render_markdown(&report),
    };

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create output directory {}", parent.display()))?;
            }
        }
        fs::write(&path, payload.as_bytes())
            .with_context(|| format!("write proof metadata to {}", path.display()))?;
    } else {
        println!("{payload}");
    }

    Ok(())
}

fn collect_proof_metadata() -> Result<ProofMetadataReport> {
    let root = workspace_root();
    let plonky3_dir = root.join("config/plonky3/setup");
    let stwo_vk = root.join("prover/prover_stwo_backend/params/vk.json");

    Ok(ProofMetadataReport {
        plonky3: collect_plonky3_metadata(&plonky3_dir)?,
        stwo: collect_stwo_metadata(&stwo_vk)?,
        blueprint: collect_blueprint_metadata()?,
    })
}

fn collect_plonky3_metadata(dir: &Path) -> Result<Plonky3Metadata> {
    let mut circuits = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read {dir:?}"))? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("read Plonky3 setup file {}", entry.path().display()))?;
        let doc: Plonky3ArtifactDoc = serde_json::from_str(&contents)
            .with_context(|| format!("parse Plonky3 setup file {}", entry.path().display()))?;
        let verifying_key = load_plonky3_artifact(dir, &doc.verifying_key)?;
        let proving_key = load_plonky3_artifact(dir, &doc.proving_key)?;
        circuits.push(Plonky3CircuitMetadata {
            name: doc.circuit,
            verifying_key_hash: blake3_hash(&verifying_key).to_string(),
            verifying_key_bytes: verifying_key.len(),
            proving_key_hash: blake3_hash(&proving_key).to_string(),
            proving_key_bytes: proving_key.len(),
        });
    }
    circuits.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Plonky3Metadata { circuits })
}

fn load_plonky3_artifact(dir: &Path, artifact: &Plonky3Artifact) -> Result<Vec<u8>> {
    let raw = if let Some(path) = artifact.value.strip_prefix('@') {
        let resolved = dir.join(path);
        fs::read(&resolved)
            .with_context(|| format!("read Plonky3 artifact {}", resolved.display()))?
    } else if artifact.value.starts_with("file:") {
        let stripped = artifact.value.trim_start_matches("file:");
        let resolved = dir.join(stripped);
        fs::read(&resolved)
            .with_context(|| format!("read Plonky3 artifact {}", resolved.display()))?
    } else {
        decode_blob(&artifact.value, artifact.encoding.as_deref())?
    };

    let bytes = match artifact
        .compression
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
    {
        Some(ref compression) if compression == "gzip" || compression == "gz" => {
            let mut decoder = GzDecoder::new(raw.as_slice());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .context("decompress Plonky3 artifact")?;
            decompressed
        }
        Some(other) => bail!("unsupported compression '{other}' in Plonky3 setup"),
        None => raw,
    };

    if let Some(expected) = artifact.byte_length {
        if bytes.len() != expected as usize {
            bail!(
                "Plonky3 artifact length mismatch: expected {expected} bytes, found {}",
                bytes.len()
            );
        }
    }

    Ok(bytes)
}

fn decode_blob(value: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Plonky3 artifact value cannot be empty");
    }

    match encoding.map(|enc| enc.to_ascii_lowercase()) {
        Some(enc) if enc != "base64" => {
            bail!("unsupported artifact encoding '{enc}' (expected base64)");
        }
        _ => BASE64
            .decode(trimmed)
            .map_err(|err| anyhow!("failed to decode base64 artifact: {err}")),
    }
}

fn collect_stwo_metadata(path: &Path) -> Result<StwoMetadata> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read STWO verifying-key manifest {}", path.display()))?;
    let file: StwoVkFile = serde_json::from_str(&contents)
        .with_context(|| format!("parse STWO verifying-key manifest {}", path.display()))?;
    let mut circuits: Vec<StwoCircuitMetadata> = file
        .circuits
        .into_iter()
        .map(|(name, circuit)| StwoCircuitMetadata {
            name,
            degree: circuit.degree,
            commitment: circuit.commitment,
        })
        .collect();
    circuits.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(StwoMetadata {
        version: file.version,
        circuits,
    })
}

fn collect_blueprint_metadata() -> Result<BlueprintMetadata> {
    let mut stages = blueprint_stage_summaries();
    stages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(BlueprintMetadata { stages })
}

fn blueprint_stage_summaries() -> Vec<BlueprintStageMetadata> {
    vec![
        BlueprintStageMetadata {
            name: "block_transition_aggregation".to_string(),
            kind: "aggregation".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Aggregates all module digests, binds them to the block header and exposes the proof registry root.".to_string(),
        },
        BlueprintStageMetadata {
            name: "consensus_attestation".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Validates Malachite BFT votes and quorum signatures for the proposed block.".to_string(),
        },
        BlueprintStageMetadata {
            name: "global_state_transition".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Applies account-level balance, stake and nonce updates while linking to the global state commitment.".to_string(),
        },
        BlueprintStageMetadata {
            name: "recursive_wrapper".to_string(),
            kind: "recursion".to_string(),
            proof_system: "plonky2".to_string(),
            constraint_count: 3,
            description: "Wraps the STWO block proof and the previous recursive accumulator into a succinct proof chain.".to_string(),
        },
        BlueprintStageMetadata {
            name: "reputation_update".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Aggregates timetoke rewards, consensus participation and penalties into updated reputation tiers.".to_string(),
        },
        BlueprintStageMetadata {
            name: "timetoke_accrual".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Checks epoch-bounded uptime proofs and updates timetoke balances.".to_string(),
        },
        BlueprintStageMetadata {
            name: "utxo_transition".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Validates consumption and creation of UTXOs across the transaction batch.".to_string(),
        },
        BlueprintStageMetadata {
            name: "zsi_onboarding".to_string(),
            kind: "base".to_string(),
            proof_system: "stwo".to_string(),
            constraint_count: 3,
            description: "Proves correct inclusion of newly approved zero-state identities.".to_string(),
        },
    ]
}

fn render_markdown(report: &ProofMetadataReport) -> String {
    let mut out = String::new();
    out.push_str("# Proof metadata summary\n\n");

    out.push_str("## Plonky3 circuits\n\n");
    out.push_str("| Circuit | Verifying key (BLAKE3) | Bytes | Proving key (BLAKE3) | Bytes |\n");
    out.push_str("| --- | --- | ---: | --- | ---: |\n");
    for circuit in &report.plonky3.circuits {
        writeln!(
            out,
            "| {} | `{}` | {} | `{}` | {} |",
            circuit.name,
            circuit.verifying_key_hash,
            circuit.verifying_key_bytes,
            circuit.proving_key_hash,
            circuit.proving_key_bytes
        )
        .expect("write markdown");
    }
    out.push('\n');

    out.push_str("## STWO circuits\n\n");
    out.push_str("| Circuit | Degree | Commitment |\n");
    out.push_str("| --- | ---: | --- |\n");
    for circuit in &report.stwo.circuits {
        writeln!(
            out,
            "| {} | {} | `{}` |",
            circuit.name, circuit.degree, circuit.commitment
        )
        .expect("write markdown");
    }
    out.push('\n');

    out.push_str("## Blueprint stages\n\n");
    out.push_str("| Stage | Kind | Proof system | Constraints | Description |\n");
    out.push_str("| --- | --- | --- | ---: | --- |\n");
    for stage in &report.blueprint.stages {
        writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            stage.name,
            stage.kind,
            stage.proof_system,
            stage.constraint_count,
            stage.description.replace('|', "\\|")
        )
        .expect("write markdown");
    }

    out
}

#[derive(Debug, Clone, Copy)]
enum MetadataFormat {
    Json,
    Markdown,
}

#[derive(Debug, Serialize)]
struct ProofMetadataReport {
    plonky3: Plonky3Metadata,
    stwo: StwoMetadata,
    blueprint: BlueprintMetadata,
}

#[derive(Debug, Serialize)]
struct Plonky3Metadata {
    circuits: Vec<Plonky3CircuitMetadata>,
}

#[derive(Debug, Serialize)]
struct Plonky3CircuitMetadata {
    name: String,
    verifying_key_hash: String,
    verifying_key_bytes: usize,
    proving_key_hash: String,
    proving_key_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct Plonky3ArtifactDoc {
    circuit: String,
    #[serde(default)]
    metadata: Option<JsonValue>,
    verifying_key: Plonky3Artifact,
    proving_key: Plonky3Artifact,
}

#[derive(Debug, Deserialize)]
struct Plonky3Artifact {
    value: String,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    byte_length: Option<u64>,
}

#[derive(Debug, Serialize)]
struct StwoMetadata {
    version: u64,
    circuits: Vec<StwoCircuitMetadata>,
}

#[derive(Debug, Serialize)]
struct StwoCircuitMetadata {
    name: String,
    degree: u64,
    commitment: String,
}

#[derive(Debug, Deserialize)]
struct StwoVkFile {
    version: u64,
    circuits: BTreeMap<String, StwoVkCircuit>,
}

#[derive(Debug, Deserialize)]
struct StwoVkCircuit {
    degree: u64,
    commitment: String,
}

#[derive(Debug, Serialize)]
struct BlueprintMetadata {
    stages: Vec<BlueprintStageMetadata>,
}

#[derive(Debug, Serialize)]
struct BlueprintStageMetadata {
    name: String,
    kind: String,
    proof_system: String,
    constraint_count: usize,
    description: String,
}
