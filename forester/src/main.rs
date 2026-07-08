use std::process::ExitCode;

use clap::Parser;
use forester::cli::{Cli, Commands};
use forester::run::RunOptions;

// Plain `fn main` (no Tokio runtime): the prover and photon clients use
// `reqwest::blocking`, which panics inside an async runtime.
fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    forester::logging::setup();

    let cli = Cli::parse();
    match cli.command {
        Commands::Start => {
            // Placeholder for the always-on worker (future work): a daemon that
            // watches every configured tree and drains queues continuously.
            // Today, `run --watch` is the drain loop; use it instead.
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
        Commands::Run {
            tree,
            settings,
            account_index,
            max_batches,
            watch,
            poll_secs,
            dry_run,
        } => {
            let options = RunOptions {
                tree,
                settings,
                account_index,
                max_batches,
                watch,
                poll_secs,
                dry_run,
            };
            match forester::run::run(options) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("error: {err:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
