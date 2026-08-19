//! `ring.toml`, the answers the wizard recorded for a generated ring.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use solana_address::Address;
use solana_keypair::{read_keypair_file, Keypair};

pub const RING_TOML: &str = "ring.toml";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingConfig {
    pub name: String,
    pub target: Target,
    #[serde(deserialize_with = "base58_address::deserialize")]
    pub program_id: Address,
    /// Deploy upgrade authority and ring authority. `~` expands to `$HOME`.
    pub authority_keypair: PathBuf,
    pub urls: Urls,
    /// Feature id to enabled. Ids come from the wizard's registry; the config
    /// carries them as data so a new feature needs no code here.
    #[serde(default)]
    pub features: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Localnet,
    Devnet,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Urls {
    pub rpc: String,
    pub indexer: String,
    pub prover: String,
    pub ring_rpc: String,
    /// The ring RPC's ed25519 service pubkey (its `health` reports it). When
    /// set, `init` accepts an auditor key from the RPC only with that key's
    /// signature on it.
    #[serde(default)]
    pub ring_rpc_pubkey: Option<String>,
}

impl RingConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn authority(&self) -> Result<Keypair> {
        let path = expand_tilde(&self.authority_keypair)?;
        read_keypair_file(&path)
            .map_err(|e| anyhow!("reading authority keypair {}: {e}", path.display()))
    }

    pub fn enabled_features(&self) -> impl Iterator<Item = &str> {
        self.features
            .iter()
            .filter(|(_, enabled)| **enabled)
            .map(|(id, _)| id.as_str())
    }
}

/// `Address` deserializes from bytes by default; the file carries base58.
mod base58_address {
    use serde::{Deserialize, Deserializer};
    use solana_address::Address;

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Address, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

pub fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let Ok(rest) = path.strip_prefix("~") else {
        return Ok(path.to_path_buf());
    };
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
name = "demo-ring"
target = "localnet"
program_id = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh"
authority_keypair = "~/.config/solana/id.json"

[urls]
rpc = "http://127.0.0.1:8899"
indexer = "http://127.0.0.1:8784"
prover = "http://127.0.0.1:3001"
ring_rpc = "http://127.0.0.1:8785"

[features]
confidential = true
auditor_visibility = true
anonymous = false
"#;

    #[test]
    fn parses_the_wizard_output_and_lists_enabled_features() {
        let config: RingConfig = toml::from_str(EXAMPLE).expect("parse");
        assert_eq!(config.target, Target::Localnet);
        assert_eq!(
            config.enabled_features().collect::<Vec<_>>(),
            vec!["auditor_visibility", "confidential"]
        );
        assert_eq!(config.urls.ring_rpc, "http://127.0.0.1:8785");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = format!("{EXAMPLE}\nextra = 1\n");
        assert!(toml::from_str::<RingConfig>(&text).is_err());
    }

    #[test]
    fn tilde_expands_to_home() {
        std::env::set_var("HOME", "/tmp/ring-home");
        assert_eq!(
            expand_tilde(Path::new("~/.config/solana/id.json")).expect("expand"),
            PathBuf::from("/tmp/ring-home/.config/solana/id.json")
        );
        assert_eq!(
            expand_tilde(Path::new("/abs/key.json")).expect("expand"),
            PathBuf::from("/abs/key.json")
        );
    }
}
