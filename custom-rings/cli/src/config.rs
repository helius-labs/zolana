//! `ring.toml`, the answers `new` recorded.

use std::{
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_keypair::Keypair;
use thiserror::Error;

use crate::{
    file::{self, FileError},
    ProjectRoot,
};

pub const RING_TOML: &str = "ring.toml";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RingConfig {
    pub name: String,
    /// `--target` overrides it for one command.
    pub target: Target,
    #[serde(with = "base58_address")]
    pub program_id: Address,
    /// Fallback for both authority keypairs.
    pub authority_keypair: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_authority_keypair: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_authority_keypair: Option<PathBuf>,
    pub localnet: Urls,
    pub devnet: Urls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Localnet,
    Devnet,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Urls {
    pub rpc: String,
    pub indexer: String,
    pub prover: String,
    pub ring_rpc: String,
    /// When set, `init` accepts an auditor key only under this service key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_rpc_pubkey: Option<String>,
}

impl Urls {
    /// Only a ring RPC on this machine takes its auditor key from `keys/`.
    pub fn ring_rpc_is_local(&self) -> bool {
        let rest = match self.ring_rpc.split_once("://") {
            Some((_, rest)) => rest,
            None => &self.ring_rpc,
        };
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        let host = match authority.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => authority,
        };
        matches!(
            host.trim_start_matches('[').trim_end_matches(']'),
            "127.0.0.1" | "localhost" | "0.0.0.0" | "::1"
        )
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    File(#[from] FileError),
    #[error("{path} has no target line")]
    NoTargetLine { path: PathBuf },
    #[error("{path} line is not KEY=VALUE, {line}")]
    DotenvLine { path: PathBuf, line: String },
    #[error("{name} is not set, put it in .env next to ring.toml")]
    UnsetVariable { name: String },
    #[error("unclosed placeholder in {text}")]
    UnclosedPlaceholder { text: String },
    #[error("HOME is not set")]
    HomeUnset,
    #[error("ring_rpc_pubkey {key} is not a base58 key")]
    RingRpcPubkey { key: String },
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Localnet => "localnet",
            Self::Devnet => "devnet",
        }
    }
}

impl RingConfig {
    /// `.env` next to ring.toml fills `${NAME}` placeholders, the environment wins.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut config: Self = file::parse_toml(path)?;
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

    pub fn urls(&self) -> &Urls {
        match self.target {
            Target::Localnet => &self.localnet,
            Target::Devnet => &self.devnet,
        }
    }

    /// The rest of the file stays byte for byte.
    pub fn set_target(path: &Path, target: Target) -> Result<(), ConfigError> {
        let text = file::read(path)?;
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
            return Err(ConfigError::NoTargetLine {
                path: path.to_path_buf(),
            });
        }
        Ok(file::write(path, updated.join("\n") + "\n")?)
    }

    pub fn config_authority(&self) -> Result<Keypair, ConfigError> {
        Ok(file::read_keypair(&expand_tilde(
            self.config_authority_keypair(),
        )?)?)
    }

    pub fn upgrade_authority(&self) -> Result<Keypair, ConfigError> {
        Ok(file::read_keypair(&expand_tilde(
            self.upgrade_authority_keypair(),
        )?)?)
    }

    pub fn config_authority_keypair(&self) -> &Path {
        self.config_authority_keypair
            .as_deref()
            .unwrap_or(&self.authority_keypair)
    }

    pub fn upgrade_authority_keypair(&self) -> &Path {
        self.upgrade_authority_keypair
            .as_deref()
            .unwrap_or(&self.authority_keypair)
    }

    pub(crate) fn resolve_keypair_paths(&mut self, root: &ProjectRoot) {
        self.authority_keypair = root.resolve(&self.authority_keypair);
        self.config_authority_keypair = self
            .config_authority_keypair
            .take()
            .map(|path| root.resolve(&path));
        self.upgrade_authority_keypair = self
            .upgrade_authority_keypair
            .take()
            .map(|path| root.resolve(&path));
    }
}

pub fn redact_url(url: &str) -> String {
    match url.split_once('?') {
        Some((base, _)) => format!("{base}?…"),
        None => url.to_owned(),
    }
}

pub fn redact_text(text: &str) -> String {
    const KEY: &str = "api-key=";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(KEY) {
        let after = start + KEY.len();
        out.push_str(&rest[..after]);
        out.push('…');
        let value_end = rest[after..]
            .find(|c: char| c == '&' || c == ')' || c == '"' || c.is_whitespace())
            .map_or(rest.len(), |end| after + end);
        rest = &rest[value_end..];
    }
    out.push_str(rest);
    out
}

pub fn expand_tilde(path: &Path) -> Result<PathBuf, ConfigError> {
    let Ok(rest) = path.strip_prefix("~") else {
        return Ok(path.to_path_buf());
    };
    let home = std::env::var_os("HOME").ok_or(ConfigError::HomeUnset)?;
    Ok(PathBuf::from(home).join(rest))
}

/// The file carries base58, not the default byte form.
mod base58_address {
    use serde::{Deserialize, Deserializer, Serializer};
    use solana_address::Address;

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Address, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }

    pub fn serialize<S: Serializer>(address: &Address, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&address.to_string())
    }
}

/// Never overrides a variable already set.
fn load_dotenv(path: &Path) -> Result<(), ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(FileError::Read {
                path: path.to_path_buf(),
                source,
            }
            .into())
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError::DotenvLine {
                path: path.to_path_buf(),
                line: line.to_owned(),
            });
        };
        let key = key.trim().strip_prefix("export ").unwrap_or(key.trim());
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value.trim().trim_matches('"'));
        }
    }
    Ok(())
}

/// An unset name is an error, a URL never goes out with a placeholder.
fn expand_env(text: &str) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| ConfigError::UnclosedPlaceholder {
                text: text.to_owned(),
            })?;
        let name = &after[..end];
        let value = std::env::var(name).map_err(|_| ConfigError::UnsetVariable {
            name: name.to_owned(),
        })?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
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
"#;

    #[test]
    fn parses_the_recorded_answers_and_round_trips() {
        let config: RingConfig = toml::from_str(EXAMPLE).expect("parse");
        assert_eq!(config.target, Target::Localnet);
        assert_eq!(config.urls().rpc, "http://127.0.0.1:8899");
        assert_eq!(config.devnet.rpc, "https://api.devnet.solana.com");
        assert_eq!(config.urls().ring_rpc, "http://127.0.0.1:8785");
        let written = toml::to_string(&config).expect("serialize");
        assert!(!written.contains("upgrade_authority_keypair"));
        assert!(!written.contains("ring_rpc_pubkey"));
        assert_eq!(
            toml::from_str::<RingConfig>(&written).expect("reparse"),
            config
        );
    }

    #[test]
    fn authority_paths_split_without_breaking_legacy_configs() {
        let split = EXAMPLE.replacen(
            "\n[localnet]",
            "\nconfig_authority_keypair = \"config.json\"\nupgrade_authority_keypair = \"upgrade.json\"\n\n[localnet]",
            1,
        );
        let config: RingConfig = toml::from_str(&split).expect("parse split authorities");
        assert_eq!(config.config_authority_keypair(), Path::new("config.json"));
        assert_eq!(
            config.upgrade_authority_keypair(),
            Path::new("upgrade.json")
        );

        let legacy: RingConfig = toml::from_str(EXAMPLE).expect("parse legacy authority");
        assert_eq!(legacy.config_authority_keypair(), legacy.authority_keypair);
        assert_eq!(legacy.upgrade_authority_keypair(), legacy.authority_keypair);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = format!("{EXAMPLE}\nextra = 1\n");
        assert!(toml::from_str::<RingConfig>(&text).is_err());
    }

    #[test]
    fn only_a_loopback_ring_rpc_counts_as_local() {
        let local = |url: &str| {
            let mut config: RingConfig = toml::from_str(EXAMPLE).expect("parse");
            config.localnet.ring_rpc = url.to_owned();
            config.urls().ring_rpc_is_local()
        };
        assert!(local("http://127.0.0.1:8785"));
        assert!(local("http://localhost:8785/"));
        assert!(local("http://[::1]:8785"));
        assert!(!local("https://d1ojzfopdqqs5r.cloudfront.net"));
        assert!(!local("http://ring.example.com:8785"));
        // A host that merely starts with a loopback name is not one.
        assert!(!local("http://localhost.example.com:8785"));
    }

    #[test]
    fn redaction_masks_query_strings_and_api_keys() {
        assert_eq!(
            redact_url("https://devnet.helius-rpc.com/?api-key=secret"),
            "https://devnet.helius-rpc.com/?…"
        );
        assert_eq!(redact_url("http://127.0.0.1:8899"), "http://127.0.0.1:8899");
        assert_eq!(
            redact_text("error sending request for url (https://x/?api-key=abc&x=1): timeout"),
            "error sending request for url (https://x/?api-key=…&x=1): timeout"
        );
        assert_eq!(redact_text("api-key=abc"), "api-key=…");
        assert_eq!(redact_text("no key here"), "no key here");
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
        std::fs::write(&path, "name = \"x\"\n").expect("write");
        assert!(matches!(
            RingConfig::set_target(&path, Target::Devnet),
            Err(ConfigError::NoTargetLine { .. })
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

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
        assert!(matches!(
            expand_env("${RING_TEST_UNSET_KEY}"),
            Err(ConfigError::UnsetVariable { .. })
        ));
        assert!(matches!(
            expand_env("${RING_TEST_KEY"),
            Err(ConfigError::UnclosedPlaceholder { .. })
        ));
    }
}
