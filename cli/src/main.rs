mod args;
mod cli_config;
mod config;
mod config_cmd;
mod http;
mod localnet;
mod merge_service_pid;
mod process;
mod prover;
mod wallet_cli;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::{
    args::{Cli, CliCommand},
    config_cmd::run_config,
    localnet::run_test_validator,
    prover::run_start_prover,
    wallet_cli::run_wallet,
};

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(CliCommand::TestValidator(opts)) => run_test_validator(*opts),
        Some(CliCommand::StartProver(opts)) => run_start_prover(opts),
        Some(CliCommand::Config { command }) => run_config(command),
        Some(CliCommand::Wallet { command }) => run_wallet(command),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
