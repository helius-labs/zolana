mod args;
mod cli_config;
mod config;
mod config_cmd;
mod http;
mod localnet;
mod process;
mod prover;
mod wallet_cli;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::{
    args::{Cli, CliCommand},
    cli_config::set_config_file_override,
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
    if let Some(path) = cli.config_file {
        set_config_file_override(path)?;
    }
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
