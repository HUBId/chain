use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    rpp_chain_cli::run_cli(|mode, options| rpp_node::run(mode, options)).await
}
