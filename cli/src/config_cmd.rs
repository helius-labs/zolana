use anyhow::{bail, Result};

use crate::args::{ConfigCommand, ConfigSetOptions};
use crate::cli_config::{
    config_file_path, default_keypair_path, CliConfigFile, DEFAULT_INDEXER_URL, DEFAULT_PROVER_URL,
    DEFAULT_RPC_URL,
};

pub(crate) fn run_config(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Get => run_config_get(),
        ConfigCommand::Set(opts) => run_config_set(opts),
    }
}

fn run_config_get() -> Result<()> {
    let path = config_file_path();
    let config = CliConfigFile::load()?;
    println!("Config File: {}", path.display());
    print_field(
        "Keypair Path",
        config.keypair.as_deref(),
        default_keypair_path().to_str(),
    );
    print_field("RPC URL", config.rpc_url.as_deref(), Some(DEFAULT_RPC_URL));
    print_field(
        "Indexer URL",
        config.indexer_url.as_deref(),
        Some(DEFAULT_INDEXER_URL),
    );
    print_field(
        "Prover URL",
        config.prover_url.as_deref(),
        Some(DEFAULT_PROVER_URL),
    );
    if let Some(tree) = &config.tree {
        println!("Tree: {tree}");
    } else {
        println!("Tree: (not set)");
    }
    Ok(())
}

fn print_field(label: &str, configured: Option<&str>, default: Option<&str>) {
    match configured {
        Some(value) => println!("{label}: {value}"),
        None => match default {
            Some(value) => println!("{label}: {value} (default)"),
            None => println!("{label}: (not set)"),
        },
    }
}

fn run_config_set(opts: ConfigSetOptions) -> Result<()> {
    if opts.keypair.is_none()
        && opts.rpc_url.is_none()
        && opts.indexer_url.is_none()
        && opts.prover_url.is_none()
        && opts.tree.is_none()
    {
        bail!("pass at least one field to set");
    }
    let mut config = CliConfigFile::load()?;
    if let Some(keypair) = opts.keypair {
        config.keypair = Some(keypair);
    }
    if let Some(rpc_url) = opts.rpc_url {
        config.rpc_url = Some(rpc_url);
    }
    if let Some(indexer_url) = opts.indexer_url {
        config.indexer_url = Some(indexer_url);
    }
    if let Some(prover_url) = opts.prover_url {
        config.prover_url = Some(prover_url);
    }
    if let Some(tree) = opts.tree {
        config.tree = Some(tree);
    }
    config.save()?;
    println!("ok config {}", config_file_path().display());
    Ok(())
}
