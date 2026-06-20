use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;

pub(crate) const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
pub(crate) const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
pub(crate) const DEFAULT_PROVER_URL: &str = "http://127.0.0.1:3001";
const CONFIG_VERSION: u8 = 1;

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
    if let Ok(path) = env::var("ZOLANA_CONFIG") {
        return PathBuf::from(path);
    }
    config_dir().join("config.json")
}

pub(crate) fn default_keypair_path() -> PathBuf {
    config_dir().join("pid.json")
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
) -> Option<&'a str> {
    cli_override.or(config.tree.as_deref())
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
        let (path, path_str) = temp_config();
        unsafe { env::set_var("ZOLANA_CONFIG", &path_str) };
        let config = CliConfigFile {
            version: CONFIG_VERSION,
            keypair: Some("/tmp/alice.pid.json".to_string()),
            rpc_url: Some("http://127.0.0.1:8900".to_string()),
            indexer_url: Some("http://127.0.0.1:8785".to_string()),
            prover_url: Some("http://127.0.0.1:3002".to_string()),
            tree: Some("Tree111111111111111111111111111111111111111".to_string()),
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
            Some("So11111111111111111111111111111111111111112")
        );
    }
}
