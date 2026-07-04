use anyhow::{bail, Result};
use solana_pubkey::Pubkey;

use crate::{
    args::{ConfigAddAssetOptions, ConfigCommand, ConfigSetOptions},
    cli_config::{
        config_file_path, default_keypair_path, CliConfigFile, DEFAULT_INDEXER_URL,
        DEFAULT_PROVER_URL, DEFAULT_RPC_URL, DEFAULT_TREE,
    },
};

pub(crate) fn run_config(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Get => run_config_get(),
        ConfigCommand::Set(opts) => run_config_set(opts),
        ConfigCommand::AssetRegistry => run_asset_registry(),
        ConfigCommand::AddAsset(opts) => run_add_asset(opts),
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
    print_field("Tree", config.tree.as_deref(), Some(DEFAULT_TREE));
    print_assets(&config);
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

fn run_asset_registry() -> Result<()> {
    let config = CliConfigFile::load()?;
    print_assets(&config);
    Ok(())
}

fn print_assets(config: &CliConfigFile) {
    if config.assets.is_empty() {
        println!("Assets: (SOL only)");
        return;
    }
    println!("Assets:");
    println!("  asset_id=1 mint=SOL");
    for asset in &config.assets {
        match &asset.token_account {
            Some(token_account) => println!(
                "  asset_id={} mint={} token_account={}",
                asset.asset_id, asset.mint, token_account
            ),
            None => println!("  asset_id={} mint={}", asset.asset_id, asset.mint),
        }
    }
}

fn run_add_asset(opts: ConfigAddAssetOptions) -> Result<()> {
    let mint = opts.mint.parse::<Pubkey>()?;
    let token_account = opts
        .token_account
        .as_deref()
        .map(str::parse::<Pubkey>)
        .transpose()?;
    let mut config = CliConfigFile::load()?;
    config.upsert_asset(mint, opts.asset_id, token_account)?;
    println!(
        "ok asset_registry mint={} asset_id={}{}",
        mint,
        opts.asset_id,
        token_account
            .map(|account| format!(" token_account={account}"))
            .unwrap_or_default()
    );
    Ok(())
}
