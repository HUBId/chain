use std::path::PathBuf;
use std::process;

use clap::Parser;

use snapshot_verify::{
    run_verification, write_report, DataSource, Execution, ExitCode, VerificationReport,
    VerifyArgs,
};

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

    if let Err(err) = write_report(&report, args.output.as_deref()) {
        eprintln!("error: {err:?}");
        process::exit(1);
    }

    process::exit(exit_code.code());
}
