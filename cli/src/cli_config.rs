use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::OnceLock,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_transaction::{Address, AssetRegistry};

pub(crate) const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub(crate) const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
pub(crate) const DEFAULT_PROVER_URL: &str = "http://127.0.0.1:3001";
pub(crate) const DEFAULT_TREE: &str = "treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8";
const CONFIG_VERSION: u8 = 1;
static CONFIG_FILE_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

#[cfg(test)]
pub(crate) static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Persistent CLI settings stored at `~/.config/zolana/config.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CliConfigFile {
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypair: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assets: Vec<LocalAssetConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LocalAssetConfig {
    pub mint: String,
    pub asset_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_account: Option<String>,
}

impl CliConfigFile {
    pub(crate) fn load() -> Result<Self> {
        let path = config_file_path();
        if !path.exists() {
            return Ok(Self {
                version: CONFIG_VERSION,
                ..Self::default()
            });
        }
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    pub(crate) fn save(&self) -> Result<()> {
        let path = config_file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to write {}", path.display()))?;
        let mut value = self.clone();
        value.version = CONFIG_VERSION;
        file.write_all(&serde_json::to_vec_pretty(&value)?)?;
        Ok(())
    }

    pub(crate) fn set_tree(&mut self, tree: &Pubkey) -> Result<()> {
        self.tree = Some(tree.to_string());
        self.save()
    }

    pub(crate) fn upsert_asset(
        &mut self,
        mint: Pubkey,
        asset_id: u64,
        token_account: Option<Pubkey>,
    ) -> Result<()> {
        let mint = mint.to_string();
        let token_account = token_account.map(|account| account.to_string());
        if let Some(asset) = self.assets.iter_mut().find(|asset| asset.mint == mint) {
            asset.asset_id = asset_id;
            if token_account.is_some() {
                asset.token_account = token_account;
            }
        } else {
            self.assets.push(LocalAssetConfig {
                mint,
                asset_id,
                token_account,
            });
        }
        self.assets.sort_by_key(|asset| asset.asset_id);
        self.save()
    }

    pub(crate) fn local_asset_registry(&self) -> Result<AssetRegistry> {
        let entries = self
            .assets
            .iter()
            .map(|asset| {
                let mint = asset.mint.parse::<Pubkey>()?;
                Ok((asset.asset_id, Address::new_from_array(mint.to_bytes())))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AssetRegistry::new(entries)?)
    }

    pub(crate) fn token_account_for_mint(&self, mint: Pubkey) -> Result<Option<Pubkey>> {
        let mint = mint.to_string();
        self.assets
            .iter()
            .find(|asset| asset.mint == mint)
            .and_then(|asset| asset.token_account.as_deref())
            .map(str::parse::<Pubkey>)
            .transpose()
            .map_err(Into::into)
    }
}

pub(crate) fn config_dir() -> PathBuf {
    if let Ok(path) = env::var("ZOLANA_CONFIG_DIR") {
        return PathBuf::from(path);
    }
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("zolana")
    } else {
        PathBuf::from(".zolana")
    }
}

pub(crate) fn config_file_path() -> PathBuf {
    if let Some(path) = CONFIG_FILE_OVERRIDE.get() {
        return path.clone();
    }
    if let Ok(path) = env::var("ZOLANA_CONFIG") {
        return PathBuf::from(path);
    }
    config_dir().join("config.json")
}

pub(crate) fn set_config_file_override(path: impl Into<PathBuf>) -> Result<()> {
    CONFIG_FILE_OVERRIDE
        .set(path.into())
        .map_err(|_| anyhow::anyhow!("CLI config file override was already set"))
}

pub(crate) fn default_keypair_path() -> PathBuf {
    config_dir().join("id.json")
}

pub(crate) fn resolve_keypair_path(cli_override: Option<&str>, config: &CliConfigFile) -> PathBuf {
    match cli_override {
        Some(path) => PathBuf::from(path),
        None => config
            .keypair
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(default_keypair_path),
    }
}

pub(crate) fn resolve_rpc_url(cli_override: Option<&str>, config: &CliConfigFile) -> String {
    cli_override
        .or(config.rpc_url.as_deref())
        .unwrap_or(DEFAULT_RPC_URL)
        .to_string()
}

pub(crate) fn resolve_indexer_url(cli_override: Option<&str>, config: &CliConfigFile) -> String {
    cli_override
        .or(config.indexer_url.as_deref())
        .unwrap_or(DEFAULT_INDEXER_URL)
        .to_string()
}

pub(crate) fn resolve_prover_url(cli_override: Option<&str>, config: &CliConfigFile) -> String {
    cli_override
        .or(config.prover_url.as_deref())
        .unwrap_or(DEFAULT_PROVER_URL)
        .to_string()
}

pub(crate) fn resolve_tree<'a>(
    cli_override: Option<&'a str>,
    config: &'a CliConfigFile,
) -> &'a str {
    cli_override
        .or(config.tree.as_deref())
        .unwrap_or(DEFAULT_TREE)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_config() -> (PathBuf, String) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "zolana-cli-config-{}-{stamp}.json",
            std::process::id()
        ));
        (path.clone(), path.display().to_string())
    }

    #[test]
    fn save_and_load_round_trips_config() {
        let _guard = CONFIG_ENV_LOCK.lock().expect("config env lock");
        let (path, path_str) = temp_config();
        unsafe { env::set_var("ZOLANA_CONFIG", &path_str) };
        let config = CliConfigFile {
            version: CONFIG_VERSION,
            keypair: Some("/tmp/alice.pid.json".to_string()),
            rpc_url: Some("http://127.0.0.1:8900".to_string()),
            indexer_url: Some("http://127.0.0.1:8785".to_string()),
            prover_url: Some("http://127.0.0.1:3002".to_string()),
            tree: Some("Tree111111111111111111111111111111111111111".to_string()),
            assets: Vec::new(),
        };
        config.save().expect("save config");
        assert_eq!(CliConfigFile::load().expect("load config"), config);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn resolve_precedence_prefers_cli_over_config() {
        let config = CliConfigFile {
            keypair: Some("/tmp/config.pid.json".to_string()),
            rpc_url: Some("http://127.0.0.1:8900".to_string()),
            indexer_url: Some("http://127.0.0.1:8785".to_string()),
            prover_url: Some("http://127.0.0.1:3002".to_string()),
            tree: Some("Tree111111111111111111111111111111111111111".to_string()),
            ..CliConfigFile::default()
        };
        assert_eq!(
            resolve_keypair_path(Some("/tmp/flag.pid.json"), &config),
            PathBuf::from("/tmp/flag.pid.json")
        );
        assert_eq!(
            resolve_rpc_url(Some("http://127.0.0.1:9999"), &config),
            "http://127.0.0.1:9999"
        );
        assert_eq!(
            resolve_tree(Some("So11111111111111111111111111111111111111112"), &config),
            "So11111111111111111111111111111111111111112"
        );
    }

    #[test]
    fn resolve_keypair_path_follows_precedence() {
        let config = CliConfigFile {
            keypair: Some("/tmp/config.json".to_string()),
            ..CliConfigFile::default()
        };

        assert_eq!(
            resolve_keypair_path(Some("/tmp/flag.json"), &config),
            PathBuf::from("/tmp/flag.json")
        );
        assert_eq!(
            resolve_keypair_path(None, &config),
            PathBuf::from("/tmp/config.json")
        );
        assert_eq!(
            resolve_keypair_path(None, &CliConfigFile::default()),
            default_keypair_path()
        );
    }

    #[test]
    fn built_in_keypair_path_is_id_json() {
        assert_eq!(
            default_keypair_path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("id.json")
        );
    }
}
