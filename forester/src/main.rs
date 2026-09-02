use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use forester::{
    cli::{Cli, Commands},
    close_nullifier_pdas::CloseNullifierPdasOptions,
    config::ForesterConfig,
    run::RunOptions,
};

// Plain `fn main` (no Tokio runtime): the prover and photon clients use
// `reqwest::blocking`, which panics inside an async runtime.
fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    forester::logging::setup();

    match dispatch(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Run one command. Each arm resolves the environment it needs and no more, so
/// `start` does not demand endpoints it never uses.
fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Start => {
            // Placeholder for the always-on worker (future work): a daemon that
            // watches every configured tree and drains queues continuously.
            // Today, `run --watch` is the drain loop; use it instead.
            tracing::info!("forester: no worker configured");
            Ok(())
        }
        Commands::Info { tree, json } => {
            forester::info::run(&ForesterConfig::from_env()?, tree, json)
        }
        Commands::Run {
            tree,
            settings,
            account_index,
            max_batches,
            watch,
            poll_secs,
            dry_run,
            metrics_address,
            proof_concurrency,
        } => {
            // Resolved before the drain loop so a missing endpoint fails at
            // startup rather than partway through an iteration.
            let config = ForesterConfig::from_env()?;

            // Served before the loop too, so a scrape during the first iteration
            // succeeds rather than connection-refusing.
            if let Some(address) = metrics_address.as_deref() {
                forester::metrics::serve(address);
            }

            forester::run::run(
                &config,
                RunOptions {
                    tree,
                    settings,
                    account_index,
                    max_batches,
                    watch,
                    poll_secs,
                    dry_run,
                    proof_concurrency,
                },
            )
        }
        Commands::CloseNullifierPdas {
            tree,
            settings,
            account_index,
            from_seq,
            max_transactions,
            watch,
            poll_secs,
        } => forester::close_nullifier_pdas::run(
            &ForesterConfig::from_env()?,
            CloseNullifierPdasOptions {
                tree,
                settings,
                account_index,
                from_seq,
                max_transactions,
                watch,
                poll_secs,
            },
        ),
    }
}
