use std::path::PathBuf;

use anyhow::Result;
use solana_pubkey::Pubkey;

use super::util::parse_pubkey;
use crate::{
    args::{NetworkWalletOptions, SyncOptions},
    cli_config::{
        resolve_indexer_url, resolve_prover_url, resolve_rpc_url, resolve_tree,
        resolve_wallet_path, CliConfigFile,
    },
};

#[derive(Debug)]
pub(crate) struct ResolvedSyncOptions {
    pub(crate) keypair_path: PathBuf,
    pub(crate) rpc_url: String,
    pub(crate) indexer_url: String,
}

#[derive(Debug)]
pub(crate) struct ResolvedNetworkOptions {
    pub(crate) sync: ResolvedSyncOptions,
    pub(crate) tree: Pubkey,
    pub(crate) prover_url: String,
    pub(crate) airdrop_lamports: Option<u64>,
}

pub(crate) fn resolve_sync(opts: &SyncOptions) -> Result<ResolvedSyncOptions> {
    let config = CliConfigFile::load()?;
    resolve_sync_with_config(opts, &config)
}

pub(crate) fn resolve_sync_with_config(
    opts: &SyncOptions,
    config: &CliConfigFile,
) -> Result<ResolvedSyncOptions> {
    Ok(ResolvedSyncOptions {
        keypair_path: resolve_wallet_path(
            opts.keypair.wallet.as_deref(),
            opts.keypair.keypair.as_deref(),
            config,
        )?,
        rpc_url: resolve_rpc_url(opts.rpc_url.as_deref(), config),
        indexer_url: resolve_indexer_url(opts.indexer_url.as_deref(), config),
    })
}

pub(crate) fn get_network_with_config(
    opts: &NetworkWalletOptions,
    config: &CliConfigFile,
) -> Result<ResolvedNetworkOptions> {
    let sync = resolve_sync_with_config(&opts.sync, config)?;
    let tree = parse_pubkey(resolve_tree(opts.tree.as_deref(), config))?;
    Ok(ResolvedNetworkOptions {
        sync,
        tree,
        prover_url: resolve_prover_url(opts.prover_url.as_deref(), config),
        airdrop_lamports: opts.airdrop_lamports,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{args::WalletKeypairOptions, cli_config::CONFIG_ENV_LOCK};

    fn temp_config(tree: Option<&str>) -> String {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zolana-cli-resolve-{}-{stamp}.json",
            std::process::id()
        ));
        let config = CliConfigFile {
            tree: tree.map(str::to_string),
            ..CliConfigFile::default()
        };
        fs::write(
            &path,
            serde_json::to_vec_pretty(&config).expect("serialize"),
        )
        .expect("write");
        path.display().to_string()
    }

    #[test]
    fn write_commands_use_default_tree_when_unset() {
        let _guard = CONFIG_ENV_LOCK.lock().expect("config env lock");
        let path = temp_config(None);
        unsafe { std::env::set_var("ZOLANA_CONFIG", &path) };
        let resolved = get_network_with_config(
            &NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        wallet: None,
                        keypair: None,
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: None,
                prover_url: None,
                airdrop_lamports: None,
            },
            &CliConfigFile::load().expect("load config"),
        )
        .expect("resolve network");
        assert_eq!(
            resolved.tree.to_string(),
            "treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8"
        );
    }

    #[test]
    fn write_commands_use_config_tree_when_flag_omitted() {
        let _guard = CONFIG_ENV_LOCK.lock().expect("config env lock");
        let path = temp_config(Some("Tree111111111111111111111111111111111111111"));
        unsafe { std::env::set_var("ZOLANA_CONFIG", &path) };
        let resolved = get_network_with_config(
            &NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        wallet: None,
                        keypair: None,
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: None,
                prover_url: None,
                airdrop_lamports: None,
            },
            &CliConfigFile::load().expect("load config"),
        )
        .expect("resolve network");
        assert_eq!(
            resolved.tree.to_string(),
            "Tree111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn write_commands_prefer_flag_tree_over_config() {
        let _guard = CONFIG_ENV_LOCK.lock().expect("config env lock");
        let path = temp_config(Some("Tree111111111111111111111111111111111111111"));
        unsafe { std::env::set_var("ZOLANA_CONFIG", &path) };
        let resolved = get_network_with_config(
            &NetworkWalletOptions {
                sync: SyncOptions {
                    keypair: WalletKeypairOptions {
                        wallet: None,
                        keypair: None,
                    },
                    rpc_url: None,
                    indexer_url: None,
                },
                tree: Some("So11111111111111111111111111111111111111112".to_string()),
                prover_url: None,
                airdrop_lamports: None,
            },
            &CliConfigFile::load().expect("load config"),
        )
        .expect("resolve network");
        assert_eq!(
            resolved.tree.to_string(),
            "So11111111111111111111111111111111111111112"
        );
    }
}
