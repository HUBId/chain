use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match rpp_node::cli::run_cli().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
    }
}
