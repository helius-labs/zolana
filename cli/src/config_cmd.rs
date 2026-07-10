use anyhow::{bail, Result};
use solana_pubkey::Pubkey;
use zolana_interface::DEFAULT_TREE_ADDRESS;

use crate::{
    args::{ConfigAddAssetOptions, ConfigCommand, ConfigField, ConfigSetOptions},
    cli_config::{
        config_file_path, default_keypair_path, CliConfigFile, DEFAULT_INDEXER_URL,
        DEFAULT_PROVER_URL, DEFAULT_RPC_URL,
    },
};

pub(crate) fn run_config(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Get => run_config_get(),
        ConfigCommand::Set(opts) => run_config_set(opts),
        ConfigCommand::Unset { field } => run_config_unset(field),
        ConfigCommand::AssetRegistry => run_asset_registry(),
        ConfigCommand::AddAsset(opts) => run_add_asset(opts),
    }
}

fn run_config_unset(field: ConfigField) -> Result<()> {
    let mut config = CliConfigFile::load()?;
    let name = match field {
        ConfigField::Keypair => {
            config.keypair = None;
            "keypair"
        }
        ConfigField::RpcUrl => {
            config.rpc_url = None;
            "rpc-url"
        }
        ConfigField::IndexerUrl => {
            config.indexer_url = None;
            "indexer-url"
        }
        ConfigField::ProverUrl => {
            config.prover_url = None;
            "prover-url"
        }
        ConfigField::Tree => {
            config.tree = None;
            "tree"
        }
    };
    config.save()?;
    println!("ok unset {name}");
    Ok(())
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
    print_field("Tree", config.tree.as_deref(), Some(DEFAULT_TREE_ADDRESS));
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
        config.tree = Some(tree.parse::<Pubkey>()?.to_string());
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
        println!("  asset_id={} mint={}", asset.asset_id, asset.mint);
    }
}

fn run_add_asset(opts: ConfigAddAssetOptions) -> Result<()> {
    let mint = opts.mint.parse::<Pubkey>()?;
    let mut config = CliConfigFile::load()?;
    config.upsert_asset(mint, opts.asset_id)?;
    println!("ok asset_registry mint={} asset_id={}", mint, opts.asset_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::cli_config::CONFIG_ENV_LOCK;

    #[test]
    fn unset_tree_removes_the_configured_override() {
        let _guard = CONFIG_ENV_LOCK.lock().expect("config env lock");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "zolana-cli-unset-{}-{stamp}.json",
            std::process::id()
        ));
        unsafe { env::set_var("ZOLANA_CONFIG", &path) };
        CliConfigFile {
            tree: Some(Pubkey::new_unique().to_string()),
            ..CliConfigFile::default()
        }
        .save()
        .expect("save config");

        run_config_unset(ConfigField::Tree).expect("unset tree");

        assert_eq!(CliConfigFile::load().expect("load config").tree, None);
        let _ = fs::remove_file(path);
    }
}
