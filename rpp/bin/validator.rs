use std::process::ExitCode;

use clap::Parser;
use rpp_node::{ConfigurationError, RunArgs, RuntimeMode};

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
    match rpp_node::bootstrap(RuntimeMode::Validator, options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => match err.downcast::<ConfigurationError>() {
            Ok(config_err) => {
                eprintln!("Error: {config_err}");
                ExitCode::from(2)
            }
            Err(err) => {
                eprintln!("{err:?}");
                ExitCode::from(1)
            }
        },
    }
}
