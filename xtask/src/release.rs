use std::env;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

use crate::workspace_root;

#[derive(Clone, Copy)]
struct ProofVersionSource {
    path: &'static str,
    label: &'static str,
}

const PROOF_VERSION_SOURCES: &[ProofVersionSource] = &[
    ProofVersionSource {
        path: "vendor/rpp-stark/src/proof/types.rs",
        label: "rpp-stark proof ABI",
    },
    ProofVersionSource {
        path: "firewood/src/proofs.rs",
        label: "Firewood proof envelope",
    },
];

const PROOF_AFFECTING_PREFIXES: &[&str] = &[
    "vendor/rpp-stark/",
    "firewood/src/proofs",
    "rpp/zk/",
    "rpp/proofs/",
    "rpp/chain/src/zk/",
    "prover/plonky3_backend/params/",
    "prover/plonky3_backend/src/",
    "prover/plonky3_backend/tests/",
    "prover/prover_stwo_backend/params/",
    "prover/prover_stwo_backend/src/",
    "prover/prover_stwo_backend/tests/",
    "prover/stwo/src/",
    "prover/stwo/tests/",
    "prover/fuzz/",
    "tests/snapshots/proof",
];

struct ProofVersionGuardConfig {
    base: Option<String>,
    verbose: bool,
    help: bool,
}

pub(crate) fn proof_version_guard(args: &[String]) -> Result<()> {
    let config = parse_proof_version_guard_args(args)?;
    if config.help {
        proof_version_guard_usage();
        return Ok(());
    }

    let workspace = workspace_root();
    let (base_commit, base_reference) = resolve_base_commit(&workspace, &config)?;
    let changed_files = list_changed_files(&workspace, &base_commit)?;
    let proof_related: Vec<String> = changed_files
        .into_iter()
        .filter(|path| is_proof_affecting(path))
        .collect();

    if proof_related.is_empty() {
        if config.verbose {
            println!(
                "proof-version-guard: no proof-affecting changes between {base_reference} and HEAD",
            );
        } else {
            println!("proof-version-guard: no proof-affecting changes detected; skipping");
        }
        return Ok(());
    }

    if config.verbose {
        println!(
            "proof-version-guard: detected proof-affecting changes in {} file(s) between {base_reference} and HEAD",
            proof_related.len()
        );
        for entry in &proof_related {
            println!("  - {entry}");
        }
    }

    let mut version_changes: Vec<(ProofVersionSource, u64, u64)> = Vec::new();
    for source in PROOF_VERSION_SOURCES {
        let base_version = read_proof_version(&workspace, &base_commit, source)?
            .ok_or_else(|| anyhow!("{} is missing in {base_reference}", source.path))?;
        let head_version = read_proof_version(&workspace, "HEAD", source)?
            .ok_or_else(|| anyhow!("{} is missing in HEAD", source.path))?;
        if base_version != head_version {
            version_changes.push((source, base_version, head_version));
        }
    }

    if version_changes.is_empty() {
        let mut message = String::new();
        message.push_str(
            "proof-version-guard: detected proof-affecting changes but PROOF_VERSION was not updated.\n",
        );
        message.push_str("Changed files:\n");
        for entry in proof_related.iter().take(20) {
            message.push_str(&format!("  - {entry}\n"));
        }
        if proof_related.len() > 20 {
            message.push_str(&format!("  ... and {} more\n", proof_related.len() - 20));
        }
        message.push_str("Update the PROOF_VERSION constants before merging:\n");
        for source in PROOF_VERSION_SOURCES {
            message.push_str(&format!("  - {} ({})\n", source.path, source.label));
        }
        bail!(message);
    }

    println!(
        "proof-version-guard: PROOF_VERSION bump detected for {} proof-affecting file(s)",
        proof_related.len()
    );
    for (source, old, new) in version_changes {
        println!("  - {} {old} -> {new} ({})", source.path, source.label);
    }
    Ok(())
}

fn parse_proof_version_guard_args(args: &[String]) -> Result<ProofVersionGuardConfig> {
    let mut config = ProofVersionGuardConfig {
        base: None,
        verbose: false,
        help: false,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--base" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--base requires a reference"))?;
                config.base = Some(value.to_string());
            }
            "--verbose" => {
                config.verbose = true;
            }
            "--help" | "-h" => {
                config.help = true;
            }
            other => {
                bail!("unknown argument '{other}' for proof-version-guard");
            }
        }
    }
    Ok(config)
}

fn resolve_base_commit(
    workspace: &Path,
    config: &ProofVersionGuardConfig,
) -> Result<(String, String)> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(base) = config.base.as_ref() {
        if !base.trim().is_empty() {
            candidates.push(base.clone());
        }
    } else {
        for key in [
            "PROOF_VERSION_GUARD_BASE",
            "GIT_BASE_REF",
            "GITHUB_BASE_REF",
        ] {
            if let Ok(value) = env::var(key) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    candidates.push(trimmed.to_string());
                }
            }
        }
    }
    candidates.push("origin/main".to_string());
    candidates.push("main".to_string());
    candidates.push("HEAD^".to_string());

    for candidate in candidates {
        if let Some(commit) = try_git_rev_parse(workspace, &candidate)? {
            if let Some(base) = try_merge_base(workspace, &commit)? {
                return Ok((base, candidate));
            } else {
                return Ok((commit, candidate));
            }
        }
        if !candidate.contains('/') {
            let with_origin = format!("origin/{candidate}");
            if let Some(commit) = try_git_rev_parse(workspace, &with_origin)? {
                if let Some(base) = try_merge_base(workspace, &commit)? {
                    return Ok((base, with_origin));
                } else {
                    return Ok((commit, with_origin));
                }
            }
        }
    }

    bail!(
        "proof-version-guard: unable to resolve a base commit. Pass --base <ref> or set PROOF_VERSION_GUARD_BASE."
    )
}

fn try_git_rev_parse(workspace: &Path, reference: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .current_dir(workspace)
        .arg("rev-parse")
        .arg("--verify")
        .arg(reference)
        .output()
        .with_context(|| format!("git rev-parse --verify {reference}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)
        .with_context(|| format!("decode git rev-parse output for {reference}"))?;
    Ok(Some(text.trim().to_string()))
}

fn try_merge_base(workspace: &Path, commit: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .current_dir(workspace)
        .arg("merge-base")
        .arg("HEAD")
        .arg(commit)
        .output()
        .with_context(|| format!("git merge-base HEAD {commit}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout).context("decode git merge-base output")?;
    Ok(Some(text.trim().to_string()))
}

fn list_changed_files(workspace: &Path, base: &str) -> Result<Vec<String>> {
    let range = format!("{base}..HEAD");
    let output = Command::new("git")
        .current_dir(workspace)
        .arg("diff")
        .arg("--name-only")
        .arg(&range)
        .output()
        .with_context(|| format!("git diff --name-only {range}"))?;
    if !output.status.success() {
        bail!("git diff --name-only {range} failed");
    }
    let text = String::from_utf8(output.stdout).context("decode git diff output")?;
    Ok(text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.replace('\\', "/"))
        .collect())
}

fn is_proof_affecting(path: &str) -> bool {
    let normalized = path.trim();
    if normalized.is_empty() {
        return false;
    }
    let normalized = normalized.replace('\\', "/");
    for prefix in PROOF_AFFECTING_PREFIXES {
        if normalized.starts_with(prefix) {
            return true;
        }
    }
    if normalized.starts_with("tests/") {
        let lower = normalized.to_ascii_lowercase();
        return lower.contains("proof")
            || lower.contains("rpp")
            || lower.contains("plonky3")
            || lower.contains("zk");
    }
    false
}

fn read_proof_version(
    workspace: &Path,
    reference: &str,
    source: &ProofVersionSource,
) -> Result<Option<u64>> {
    let spec = format!("{reference}:{}", source.path);
    let output = Command::new("git")
        .current_dir(workspace)
        .arg("show")
        .arg(&spec)
        .output()
        .with_context(|| format!("git show {spec}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout).context("decode git show output")?;
    Ok(extract_proof_version(&text))
}

fn extract_proof_version(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if !(trimmed.contains("PROOF_VERSION") && trimmed.contains('=')) {
            continue;
        }
        if !trimmed.starts_with("pub const PROOF_VERSION") {
            continue;
        }
        let after_equals = trimmed.split('=').nth(1)?.trim();
        let number: String = after_equals
            .chars()
            .skip_while(|ch| ch.is_whitespace())
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        if number.is_empty() {
            continue;
        }
        if let Ok(value) = number.parse::<u64>() {
            return Some(value);
        }
    }
    None
}

fn proof_version_guard_usage() {
    eprintln!(
        "usage: cargo xtask proof-version-guard [--base <ref>] [--verbose]\n\nVerifies that PROOF_VERSION changes accompany proof-affecting code or vector updates."
    );
}

#[cfg(test)]
mod tests {
    use super::{extract_proof_version, is_proof_affecting};

    #[test]
    fn parses_version_constant() {
        let input = "pub const PROOF_VERSION: u16 = 7;";
        assert_eq!(extract_proof_version(input), Some(7));
    }

    #[test]
    fn ignores_lines_without_constant() {
        let input = "const OTHER: u16 = 3;";
        assert_eq!(extract_proof_version(input), None);
    }

    #[test]
    fn vendor_tree_is_proof_affecting() {
        assert!(is_proof_affecting("vendor/rpp-stark/src/proof/verifier.rs"));
        assert!(is_proof_affecting(
            "vendor\\rpp-stark\\vectors\\stwo\\mini\\header.json"
        ));
    }
}
