use std::process::ExitCode;

use clap::Parser;
use rpp_node::{RunArgs, RuntimeMode};

#[derive(Parser)]
#[command(author, version, about = "Run the rpp validator runtime", long_about = None)]
struct ValidatorCli {
    #[command(flatten)]
    args: RunArgs,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = ValidatorCli::parse();
    let options = cli.args.into_bootstrap_options(RuntimeMode::Validator);
    let handle =
        tokio::spawn(async move { rpp_node::bootstrap(RuntimeMode::Validator, options).await });

    match handle.await {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code() as u8)
        }
        Err(join_err) => {
            if join_err.is_panic() {
                let message = panic_payload_to_string(join_err.into_panic());
                eprintln!("runtime panicked: {message}");
            } else {
                eprintln!("runtime task failed: {join_err}");
            }
            ExitCode::from(4)
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send + 'static>) -> String {
    if let Ok(message) = payload.downcast::<String>() {
        *message
    } else if let Ok(message) = payload.downcast::<&'static str>() {
        (*message).to_string()
    } else {
        "unknown panic".to_string()
    }
}
