use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{apply_feature_flags, workspace_root};

const SNAPSHOT_DIR: &str = "docs/cli/snapshots";
const ARTIFACT_DIR: &str = "target/cli-smoke";

#[derive(Clone, Copy)]
struct SmokeProfile {
    /// Identifier appended to snapshot and artefact directories.
    name: &'static str,
    /// Environment overrides applied while executing this profile.
    env_overrides: &'static [EnvOverride],
}

#[derive(Clone, Copy)]
struct EnvOverride {
    key: &'static str,
    value: Option<&'static str>,
}

struct SmokeCase {
    /// Identifier used for snapshot/artefact filenames.
    name: &'static str,
    /// Arguments passed to the CLI after the `--` separator.
    args: &'static [&'static str],
}

impl SmokeCase {
    fn snapshot_path(&self, root: &Path) -> PathBuf {
        root.join(format!("{}.stdout", self.name))
    }

    fn artefact_path(&self, root: &Path) -> PathBuf {
        root.join(format!("{}.actual", self.name))
    }
}

pub(crate) fn run_cli_smoke(args: &[String]) -> Result<()> {
    let mut record = false;
    for arg in args {
        match arg.as_str() {
            "--record" => record = true,
            "--help" | "-h" => {
                eprintln!(
                    "usage: cargo xtask test-cli [--record]\n\nRuns chain-cli help/version smoke checks. When --record is provided the command rewrites the snapshots in docs/cli/snapshots."
                );
                return Ok(());
            }
            other => bail!("unknown argument for test-cli: {other}"),
        }
    }

    let workspace = workspace_root();
    let snapshot_root = workspace.join(SNAPSHOT_DIR);
    let artefact_root = workspace.join(ARTIFACT_DIR);

    if record {
        fs::create_dir_all(&snapshot_root)
            .with_context(|| format!("create snapshot directory {}", snapshot_root.display()))?;
    } else {
        if artefact_root.exists() {
            fs::remove_dir_all(&artefact_root).with_context(|| {
                format!("clear previous artefacts under {}", artefact_root.display())
            })?;
        }
        fs::create_dir_all(&artefact_root)
            .with_context(|| format!("create artefact directory {}", artefact_root.display()))?;
    }

    let profiles = [
        SmokeProfile {
            name: "default",
            env_overrides: &[
                EnvOverride {
                    key: "XTASK_NO_DEFAULT_FEATURES",
                    value: None,
                },
                EnvOverride {
                    key: "XTASK_FEATURES",
                    value: None,
                },
            ],
        },
        SmokeProfile {
            name: "runtime-cli",
            env_overrides: &[
                EnvOverride {
                    key: "XTASK_NO_DEFAULT_FEATURES",
                    value: Some("1"),
                },
                EnvOverride {
                    key: "XTASK_FEATURES",
                    value: Some("runtime-cli"),
                },
            ],
        },
    ];

    let cases = [
        SmokeCase {
            name: "chain-cli-help",
            args: &["--help"],
        },
        SmokeCase {
            name: "chain-cli-version",
            args: &["--version"],
        },
        SmokeCase {
            name: "chain-cli-node-version",
            args: &["node", "--version"],
        },
        SmokeCase {
            name: "chain-cli-wallet-version",
            args: &["wallet", "--version"],
        },
        SmokeCase {
            name: "chain-cli-hybrid-version",
            args: &["hybrid", "--version"],
        },
        SmokeCase {
            name: "chain-cli-validator-version",
            args: &["validator", "--version"],
        },
    ];

    for profile in &profiles {
        let profile_snapshot_root = snapshot_root.join(profile.name);
        let profile_artefact_root = artefact_root.join(profile.name);

        with_profile_env(profile, || {
            for case in &cases {
                validate_case(
                    profile,
                    case,
                    record,
                    &profile_snapshot_root,
                    &profile_artefact_root,
                )?;
            }
            Ok(())
        })?;

        if !record
            && profile_artefact_root
                .read_dir()
                .map(|mut dir| dir.next().is_none())
                .unwrap_or(true)
        {
            let _ = fs::remove_dir(&profile_artefact_root);
        }
    }

    if !record && artefact_root.read_dir()?.next().is_none() {
        // If no artefacts were produced, remove the directory to keep the target tree tidy.
        let _ = fs::remove_dir(&artefact_root);
    }

    Ok(())
}

fn validate_case(
    profile: &SmokeProfile,
    case: &SmokeCase,
    record: bool,
    snapshot_root: &Path,
    artefact_root: &Path,
) -> Result<()> {
    let output = execute_cli(case.args)?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{} profile: chain-cli {:?} exited with status {}\nstdout:\n{}\nstderr:\n{}",
            profile.name,
            case.args,
            output.status,
            stdout,
            stderr
        );
    }

    let stderr = String::from_utf8(&output.stderr).context("decode CLI stderr")?;
    if !stderr.trim().is_empty() {
        bail!(
            "{} profile: chain-cli {:?} produced stderr output:\n{}",
            profile.name,
            case.args,
            stderr
        );
    }

    let actual = normalize(&String::from_utf8(output.stdout).context("decode CLI stdout")?);
    let snapshot_path = case.snapshot_path(snapshot_root);

    if record {
        if let Some(parent) = snapshot_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create snapshot parent directory {}", parent.display())
            })?;
        }
        fs::write(&snapshot_path, actual.as_bytes())
            .with_context(|| format!("write snapshot {}", snapshot_path.display()))?;
        return Ok(());
    }

    let expected = fs::read_to_string(&snapshot_path).with_context(|| {
        format!(
            "read expected output for {:?} from {}",
            case.args,
            snapshot_path.display()
        )
    })?;
    let expected = normalize(&expected);

    if expected != actual {
        let artefact_path = case.artefact_path(artefact_root);
        if let Some(parent) = artefact_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create artefact parent directory {}", parent.display())
            })?;
        }
        fs::write(&artefact_path, actual.as_bytes())
            .with_context(|| format!("write artefact {}", artefact_path.display()))?;
        bail!(
            "{} profile: chain-cli {:?} output drifted from snapshot. Expected {}. Updated output written to {}.",
            profile.name,
            case.args,
            snapshot_path.display(),
            artefact_path.display()
        );
    }

    Ok(())
}

fn execute_cli(args: &[&str]) -> Result<std::process::Output> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("run")
        .arg("--locked")
        .arg("--quiet")
        .arg("--bin")
        .arg("chain-cli");
    apply_feature_flags(&mut command);
    command.arg("--");
    command.args(args);
    command
        .output()
        .with_context(|| format!("run chain-cli {:?}", args))
}

fn normalize(text: &str) -> String {
    text.replace('\r', "")
}

fn with_profile_env<F>(profile: &SmokeProfile, action: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let mut previous = Vec::with_capacity(profile.env_overrides.len());
    for override_var in profile.env_overrides {
        let old = env::var(override_var.key).ok();
        previous.push((override_var.key, old));
        match override_var.value {
            Some(value) => env::set_var(override_var.key, value),
            None => env::remove_var(override_var.key),
        }
    }

    let result = action();

    for (key, old) in previous.into_iter().rev() {
        if let Some(value) = old {
            env::set_var(key, value);
        } else {
            env::remove_var(key);
        }
    }

    result
}
