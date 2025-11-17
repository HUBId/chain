use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    rpp_node::cli::run_cli().await
}
