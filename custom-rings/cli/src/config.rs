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
    /// The cluster the CLI and `just` act on. `just localnet` and `just devnet`
    /// set it, `--target` overrides it for one command.
    pub target: Target,
    #[serde(deserialize_with = "base58_address::deserialize")]
    pub program_id: Address,
    /// Deploy upgrade authority and ring authority. `~` expands to `$HOME`.
    pub authority_keypair: PathBuf,
    pub localnet: Urls,
    pub devnet: Urls,
    /// Feature id to enabled. Ids come from the wizard's registry; the config
    /// carries them as data so a new feature needs no code here.
    #[serde(default)]
    pub features: BTreeMap<String, bool>,
    /// What the enabled features enforce on chain. `init` writes it.
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Mints the ring accepts, `SOL` for native SOL. Absent means any asset.
    pub allowed_assets: Option<Vec<String>>,
    /// Withdrawal rule for assets without their own entry, `open`, `blocked`
    /// or `approval`. Absent means open.
    pub withdrawals: Option<String>,
    /// Per-asset withdrawal rule, mint to `open` / `blocked` / `approval`.
    #[serde(default)]
    pub asset_withdrawals: BTreeMap<String, String>,
    /// The key that approves withdrawals under an `approval` rule.
    pub approver: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Localnet,
    Devnet,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Localnet => "localnet",
            Self::Devnet => "devnet",
        }
    }
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
    /// Reads `ring.toml`, loads a `.env` next to it (values already in the
    /// environment win), and expands `${NAME}` in every URL. Secrets such as an
    /// RPC API key live in `.env`, which the generated ring ignores in git.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        load_dotenv(&path.with_file_name(".env"))?;
        for urls in [&mut config.localnet, &mut config.devnet] {
            for url in [
                &mut urls.rpc,
                &mut urls.indexer,
                &mut urls.prover,
                &mut urls.ring_rpc,
            ] {
                *url = expand_env(url)?;
            }
        }
        Ok(config)
    }

    /// The service URLs of the active target.
    pub fn urls(&self) -> &Urls {
        match self.target {
            Target::Localnet => &self.localnet,
            Target::Devnet => &self.devnet,
        }
    }

    /// Rewrites the `target` line of `path` in place, the rest of the file
    /// stays byte for byte.
    pub fn set_target(path: &Path, target: Target) -> Result<()> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut replaced = false;
        let updated: Vec<String> = text
            .lines()
            .map(|line| {
                if line.starts_with("target = ") {
                    replaced = true;
                    format!("target = \"{}\"", target.as_str())
                } else {
                    line.to_owned()
                }
            })
            .collect();
        if !replaced {
            return Err(anyhow!("{} has no `target = ...` line", path.display()));
        }
        std::fs::write(path, updated.join("\n") + "\n")
            .with_context(|| format!("writing {}", path.display()))
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

/// `Address` deserializes from bytes by default and the file carries base58.
mod base58_address {
    use serde::{Deserialize, Deserializer};
    use solana_address::Address;

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Address, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// `KEY=VALUE` lines into the process environment, comments and blanks
/// skipped, without overriding what is already set. A missing file is fine.
fn load_dotenv(path: &Path) -> Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(anyhow!(
                "{}: expected KEY=VALUE, got {line}",
                path.display()
            ));
        };
        let key = key.trim().strip_prefix("export ").unwrap_or(key.trim());
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value.trim().trim_matches('"'));
        }
    }
    Ok(())
}

/// Replaces every `${NAME}` with the environment variable, failing on an unset
/// one so a URL never goes out with the placeholder in it.
fn expand_env(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unclosed ${{ in {text}"))?;
        let name = &after[..end];
        let value = std::env::var(name)
            .map_err(|_| anyhow!("{name} is not set, put it in .env next to ring.toml"))?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
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

[localnet]
rpc = "http://127.0.0.1:8899"
indexer = "http://127.0.0.1:8784"
prover = "http://127.0.0.1:3001"
ring_rpc = "http://127.0.0.1:8785"

[devnet]
rpc = "https://api.devnet.solana.com"
indexer = "http://127.0.0.1:8784"
prover = "http://127.0.0.1:3001"
ring_rpc = "http://127.0.0.1:8785"

[features]
confidential = true
auditor_visibility = true
allowed_assets = true
anonymous = false

[policy]
allowed_assets = ["SOL", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"]
withdrawals = "blocked"
approver = "2GNuM5ksdfNxGNbwf2hrnND9FHgQsdju7vz8CyGd7Zjy"

[policy.asset_withdrawals]
SOL = "approval"
"#;

    #[test]
    fn parses_the_wizard_output_and_lists_enabled_features() {
        let config: RingConfig = toml::from_str(EXAMPLE).expect("parse");
        assert_eq!(config.target, Target::Localnet);
        assert_eq!(config.urls().rpc, "http://127.0.0.1:8899");
        assert_eq!(config.devnet.rpc, "https://api.devnet.solana.com");
        assert_eq!(
            config.enabled_features().collect::<Vec<_>>(),
            vec!["allowed_assets", "auditor_visibility", "confidential"]
        );
        assert_eq!(config.urls().ring_rpc, "http://127.0.0.1:8785");
        assert_eq!(
            config.policy.allowed_assets.as_deref().map(<[String]>::len),
            Some(2)
        );
        assert_eq!(config.policy.withdrawals.as_deref(), Some("blocked"));
        assert_eq!(
            config
                .policy
                .asset_withdrawals
                .get("SOL")
                .map(String::as_str),
            Some("approval")
        );
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

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn set_target_rewrites_only_the_target_line() {
        let dir = std::env::temp_dir().join(format!("ring-toml-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ring.toml");
        std::fs::write(
            &path,
            "name = \"x\"\ntarget = \"localnet\"\n\n[localnet]\nrpc = \"a\"\n",
        )
        .expect("write");
        RingConfig::set_target(&path, Target::Devnet).expect("set");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "name = \"x\"\ntarget = \"devnet\"\n\n[localnet]\nrpc = \"a\"\n"
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    #[test]
    fn urls_expand_env_placeholders_and_refuse_unset_ones() {
        std::env::set_var("RING_TEST_KEY", "k1");
        assert_eq!(
            expand_env("https://x/?api-key=${RING_TEST_KEY}").expect("expand"),
            "https://x/?api-key=k1"
        );
        assert_eq!(
            expand_env("http://127.0.0.1:8899").expect("plain"),
            "http://127.0.0.1:8899"
        );
        assert!(expand_env("${RING_TEST_UNSET_KEY}").is_err());
    }
}
