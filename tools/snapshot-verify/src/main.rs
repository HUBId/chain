use std::path::PathBuf;
use std::process;
use std::sync::Once;

use clap::Parser;

use snapshot_verify::{
    run_verification, write_report, DataSource, Execution, ExitCode, VerificationReport, VerifyArgs,
};

const SNAPSHOT_VERIFY_FAILURE_METRIC: &str = "snapshot_verify_failures_total";
static SNAPSHOT_METRIC_REGISTER: Once = Once::new();

fn record_snapshot_failure(exit_code: ExitCode, manifest: &PathBuf) {
    SNAPSHOT_METRIC_REGISTER.call_once(|| {
        metrics::describe_counter!(
            SNAPSHOT_VERIFY_FAILURE_METRIC,
            "Total number of snapshot verification failures observed while packaging release snapshots",
        );
    });

    let manifest_label = manifest.display().to_string();
    metrics::counter!(
        SNAPSHOT_VERIFY_FAILURE_METRIC,
        "manifest" => manifest_label,
        "exit_code" => exit_code_label(exit_code),
    )
    .increment(1);
}

fn exit_code_label(exit_code: ExitCode) -> &'static str {
    match exit_code {
        ExitCode::Success => "success",
        ExitCode::SignatureInvalid => "signature_invalid",
        ExitCode::ChunkMismatch => "chunk_mismatch",
        ExitCode::Fatal => "fatal",
    }
}

#[derive(Parser, Debug)]
#[command(
    about = "Validate pruning snapshot manifests against local chunks",
    version
)]
struct Args {
    /// Path to the snapshot chunk manifest JSON (e.g. snapshots/manifest/chunks.json)
    #[arg(long)]
    manifest: PathBuf,

    /// Path to the detached manifest signature file (base64 or hex encoded)
    #[arg(long)]
    signature: PathBuf,

    /// Path to the Ed25519 public key used to verify the manifest signature (base64 or hex encoded)
    #[arg(long = "public-key")]
    public_key: PathBuf,

    /// Directory containing chunk files referenced by the manifest (defaults to <manifest>/../chunks)
    #[arg(long = "chunk-root")]
    chunk_root: Option<PathBuf>,

    /// Emit periodic checksum progress while streaming snapshot chunks
    #[arg(long, default_value_t = false)]
    verbose_progress: bool,

    /// Optional path to write the JSON verification report to. Defaults to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    let verify_args = VerifyArgs {
        manifest: args.manifest.clone(),
        signature: args.signature.clone(),
        public_key: DataSource::Path(args.public_key.clone()),
        chunk_root: args.chunk_root.clone(),
        verbose_progress: args.verbose_progress,
    };

    let mut report = VerificationReport::new(&verify_args);
    let execution = run_verification(&verify_args, &mut report);
    let exit_code = match execution {
        Execution::Completed { exit_code } => exit_code,
        Execution::Fatal { exit_code, error } => {
            report.errors.push(error);
            exit_code
        }
    };

    if exit_code != ExitCode::Success {
        record_snapshot_failure(exit_code, &args.manifest);
    }

    if let Err(err) = write_report(&report, args.output.as_deref()) {
        eprintln!("error: {err:?}");
        process::exit(1);
    }

    process::exit(exit_code.code());
}
