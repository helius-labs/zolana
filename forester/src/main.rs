use std::process::ExitCode;

use clap::Parser;
use forester::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    forester::logging::setup();

    let cli = Cli::parse();
    match cli.command {
        Commands::Start => {
            tracing::info!("forester: no worker configured");
            ExitCode::SUCCESS
        }
        Commands::Info { tree, json } => match forester::info::run(tree, json) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err:#}");
                ExitCode::FAILURE
            }
        },
    }
}
