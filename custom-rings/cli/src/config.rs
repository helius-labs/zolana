//! `ring.toml`, the answers `new` recorded.

use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, ensure, Context as _, Result};
use custom_ring_sdk::CoSignScope;
use serde::{Deserialize, Serialize};
use solana_address::{error::ParseAddressError, Address};
use solana_keypair::Keypair;
use toml_edit::{DocumentMut, Item};
use zolana_client::ProverClient;
use zolana_transaction::SOL_MINT;

use crate::{
    file,
    macros::{named_enum, serde_via_str},
    policy::{render, PolicySpec},
};

pub const RING_TOML: &str = "ring.toml";

const fn required_deposit_audit() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RingConfig {
    pub name: String,
    /// `--target` overrides it for one command.
    pub target: Target,
    pub program_id: Base58Address,
    /// Fallback for both authority keypairs.
    pub authority_keypair: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_authority_keypair: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_authority_keypair: Option<PathBuf>,
    /// Presence selects the policy tier, `init` pins the compiled table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySpec>,
    /// Applied by `cosigner set` without flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosigner: Option<CoSignerSpec>,
    /// Retained for older ring.toml files. A false value is normalized at init.
    #[serde(default = "required_deposit_audit")]
    pub deposit_audit: bool,
    pub localnet: Urls,
    pub devnet: Urls,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CoSignerSpec {
    pub key: Base58Address,
    pub scope: Vec<CoSignClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<ThresholdSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct ThresholdSpec {
    pub mint: Base58Address,
    pub above: u64,
}

/// `sol` in any case names the native token, base58 any other mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mint(pub Address);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Base58Address(pub Address);

serde_via_str!(Mint, Base58Address);

named_enum! {
    pub enum Target("target") {
        Localnet = "localnet",
        Devnet = "devnet",
    }
}

named_enum! {
    pub enum CoSignClass("operation class") {
        Transfers = "transfers",
        Deposits = "deposits",
        Withdrawals = "withdrawals",
    }
}

named_enum! {
    pub enum Service("service") {
        Rpc = "rpc",
        Indexer = "indexer",
        Prover = "prover",
        RingRpc = "ring-rpc",
    }
}

/// One value per cluster, a missing table reads as the default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    deny_unknown_fields,
    bound(
        serialize = "T: Serialize + Default + PartialEq",
        deserialize = "T: Deserialize<'de> + Default"
    )
)]
pub struct PerCluster<T> {
    #[serde(default, skip_serializing_if = "is_default")]
    pub localnet: T,
    #[serde(default, skip_serializing_if = "is_default")]
    pub devnet: T,
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
    /// `false` sends the prover plaintext witnesses, only for a prover the operator runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_tee: Option<bool>,
}

impl CoSignClass {
    pub const fn scope(self) -> CoSignScope {
        match self {
            Self::Transfers => CoSignScope::TRANSFERS,
            Self::Deposits => CoSignScope::DEPOSITS,
            Self::Withdrawals => CoSignScope::WITHDRAWALS,
        }
    }
}

impl CoSignerSpec {
    /// `None` without a class, the program refuses an empty scope.
    pub fn scope(&self) -> Option<CoSignScope> {
        self.scope
            .iter()
            .map(|class| class.scope())
            .reduce(|scope, class| scope | class)
    }
}

impl FromStr for ThresholdSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (mint, above) = value.split_once('=').ok_or("expected <mint>=<amount>")?;
        Ok(Self {
            mint: Base58Address(mint.parse::<Mint>()?.0),
            above: above
                .parse()
                .map_err(|_| format!("{above} is not an amount"))?,
        })
    }
}

impl FromStr for Mint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let sol = value.eq_ignore_ascii_case("sol").then_some(SOL_MINT);
        let mint = sol.map_or_else(|| value.parse(), Ok);
        mint.map(Self).map_err(|_| format!("{value} is not a mint"))
    }
}

impl fmt::Display for Mint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 == SOL_MINT {
            true => f.write_str("sol"),
            false => fmt::Display::fmt(&self.0, f),
        }
    }
}

impl FromStr for Base58Address {
    type Err = ParseAddressError;

    fn from_str(value: &str) -> Result<Self, ParseAddressError> {
        value.parse().map(Self)
    }
}

impl fmt::Display for Base58Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<T> PerCluster<T> {
    pub fn get(&self, target: Target) -> &T {
        match target {
            Target::Localnet => &self.localnet,
            Target::Devnet => &self.devnet,
        }
    }

    pub fn get_mut(&mut self, target: Target) -> &mut T {
        match target {
            Target::Localnet => &mut self.localnet,
            Target::Devnet => &mut self.devnet,
        }
    }
}

impl<T: Default + PartialEq> PerCluster<T> {
    pub fn is_empty(&self) -> bool {
        is_default(&self.localnet) && is_default(&self.devnet)
    }
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

impl Urls {
    pub fn prover_client(&self) -> ProverClient {
        let prover = ProverClient::new(self.prover.clone());
        match self.prover_tee {
            Some(false) => prover.without_tee(),
            _ => prover,
        }
    }

    pub fn service(&self, service: Service) -> &str {
        match service {
            Service::Rpc => &self.rpc,
            Service::Indexer => &self.indexer,
            Service::Prover => &self.prover,
            Service::RingRpc => &self.ring_rpc,
        }
    }

    /// The explicit port only, a scheme default is `None`.
    pub fn port(url: &str) -> Option<u16> {
        reqwest::Url::parse(url).ok()?.port()
    }

    /// A loopback, unspecified or `localhost` host.
    pub fn is_local(url: &str) -> bool {
        let Some(url) = reqwest::Url::parse(url).ok() else {
            return false;
        };
        let host = url.host_str().unwrap_or_default();
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
    }

    /// Only a ring RPC on this machine takes its auditor key from `keys/`.
    pub fn ring_rpc_is_local(&self) -> bool {
        Self::is_local(&self.ring_rpc)
    }
}

impl RingConfig {
    /// `.env` next to ring.toml fills `${NAME}` placeholders, the environment wins.
    pub fn load(path: &Path) -> Result<Self> {
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

    /// `ring.toml` as text, the `[policy]` table last with its comments.
    pub fn render(&self) -> Result<String> {
        let plain = Self {
            policy: None,
            ..self.clone()
        };
        let mut document: DocumentMut = toml::to_string(&plain)?.parse()?;
        if let Some(policy) = &self.policy {
            document.insert("policy", Item::Table(render(policy)?));
        }
        Ok(document.to_string())
    }

    /// The rest of the file stays byte for byte.
    pub fn set_target(path: &Path, target: Target) -> Result<()> {
        edit(path, |document| {
            ensure!(
                document.contains_key("target"),
                "{} has no target line",
                path.display()
            );
            document["target"] = toml_edit::value(target.as_str());
            Ok(())
        })
    }

    pub fn set_deposit_audit(path: &Path, required: bool) -> Result<()> {
        ensure!(required, "deposit auditing is mandatory");
        edit(path, |document| {
            document["deposit_audit"] = toml_edit::value(required);
            Ok(())
        })
    }

    pub fn config_authority(&self) -> Result<Keypair> {
        file::read_keypair(&expand_tilde(self.config_authority_keypair())?)
    }

    pub fn upgrade_authority(&self) -> Result<Keypair> {
        file::read_keypair(&expand_tilde(self.upgrade_authority_keypair())?)
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

    pub(crate) fn resolve_keypair_paths(&mut self, resolve: impl Fn(&Path) -> PathBuf) {
        self.authority_keypair = resolve(&self.authority_keypair);
        for path in [
            &mut self.config_authority_keypair,
            &mut self.upgrade_authority_keypair,
        ]
        .into_iter()
        .flatten()
        {
            *path = resolve(path);
        }
    }
}

fn edit(path: &Path, change: impl FnOnce(&mut DocumentMut) -> Result<()>) -> Result<()> {
    let mut document: DocumentMut = file::read(path)?
        .parse()
        .with_context(|| format!("cannot parse {}", path.display()))?;
    change(&mut document)?;
    file::write(path, document.to_string())
}

pub fn redact_url(url: &str) -> String {
    reqwest::Url::parse(url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| "invalid URL".to_owned())
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

pub fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let Ok(rest) = path.strip_prefix("~") else {
        return Ok(path.to_path_buf());
    };
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(rest))
}

/// Never overrides a variable already set.
fn load_dotenv(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for line in file::read(path)?.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("{} line is not KEY=VALUE, {line}", path.display()))?;
        let key = key.trim().strip_prefix("export ").unwrap_or(key.trim());
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value.trim().trim_matches('"'));
        }
    }
    Ok(())
}

/// An unset name is an error, a URL never goes out with a placeholder.
fn expand_env(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unclosed placeholder in {text}"))?;
        let name = &after[..end];
        let value = std::env::var(name)
            .map_err(|_| anyhow!("{name} is not set, put it in .env next to ring.toml"))?;
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
    fn prover_tee_false_sends_a_remote_prover_plaintext() {
        let urls = |prover_tee: Option<bool>| Urls {
            rpc: "https://api.devnet.solana.com".to_owned(),
            indexer: "https://indexer.example".to_owned(),
            prover: "https://prover.example".to_owned(),
            ring_rpc: "https://ring-rpc.example".to_owned(),
            ring_rpc_pubkey: None,
            prover_tee,
        };
        assert!(!urls(Some(false)).prover_client().has_tee());
        assert!(urls(None).prover_client().has_tee());
        assert!(urls(Some(true)).prover_client().has_tee());

        let parsed: Urls = toml::from_str(
            "rpc = \"r\"\nindexer = \"i\"\nprover = \"p\"\nring_rpc = \"g\"\nprover_tee = false\n",
        )
        .expect("ring.toml urls");
        assert_eq!(parsed.prover_tee, Some(false));
    }

    #[test]
    fn port_reads_the_authority_only() {
        assert_eq!(Urls::port("http://127.0.0.1:8899"), Some(8899));
        assert_eq!(Urls::port("http://[::1]:8785/path?x=1:2"), Some(8785));
        assert_eq!(Urls::port("http://localhost"), None);
        assert_eq!(Urls::port("https://example.com/?key=1:2"), None);
    }

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
        assert!(!written.contains("policy"));
        assert_eq!(
            toml::from_str::<RingConfig>(&written).expect("reparse"),
            config
        );
    }

    #[test]
    fn deposit_audit_defaults_required_and_old_false_configs_still_decode() {
        let config: RingConfig = toml::from_str(EXAMPLE).unwrap();
        assert!(config.deposit_audit);
        assert!(config.render().unwrap().contains("deposit_audit = true"));
        let enabled = format!("deposit_audit = true\n{EXAMPLE}");
        let config: RingConfig = toml::from_str(&enabled).unwrap();
        assert!(config.deposit_audit);
        let historical = format!("deposit_audit = false\n{EXAMPLE}");
        let config: RingConfig = toml::from_str(&historical).unwrap();
        assert!(!config.deposit_audit);
    }

    #[test]
    fn an_empty_policy_table_selects_the_policy_tier() {
        let text = EXAMPLE.replacen("\n[localnet]", "\n[policy]\n\n[localnet]", 1);
        let config: RingConfig = toml::from_str(&text).expect("parse");
        let policy = config.policy.as_ref().expect("policy tier");
        assert!(policy.rules.is_empty());
        assert!(policy.sources.is_empty());
        let rendered = config.render().expect("render");
        assert!(rendered.contains(&format!(
            "[policy]\n# every policy transfer binds the named address tree\naddress_tree = \"{}\"",
            zolana_interface::pda::tree(0)
        )));
        let mut normalized = config;
        normalized.policy.as_mut().expect("policy").address_tree =
            Some(Base58Address(zolana_interface::pda::tree(0)));
        assert_eq!(
            toml::from_str::<RingConfig>(&rendered).expect("reparse"),
            normalized
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
        assert!(local("http://0.0.0.0:8785"));
        assert!(!local("https://d24brah9h1i4q9.cloudfront.net"));
        assert!(!local("http://ring.example.com:8785"));
        // A host that merely starts with a loopback name is not one.
        assert!(!local("http://localhost.example.com:8785"));
    }

    #[test]
    fn one_mint_spelling_serves_every_flag() {
        for sol in ["sol", "SOL", "Sol"] {
            assert_eq!(sol.parse::<Mint>(), Ok(Mint(SOL_MINT)));
        }
        assert_eq!(Mint(SOL_MINT).to_string(), "sol");
        let mint = Address::new_from_array([7; 32]);
        assert_eq!(mint.to_string().parse::<Mint>(), Ok(Mint(mint)));
        assert!("solana".parse::<Mint>().is_err());
        let sol: ThresholdSpec = "SOL=5".parse().expect("parses");
        assert_eq!((sol.mint.0, sol.above), (SOL_MINT, 5));
        assert_eq!(
            "5".parse::<ThresholdSpec>(),
            Err("expected <mint>=<amount>".to_owned())
        );
        assert!("sol=many".parse::<ThresholdSpec>().is_err());
        assert!("mint=1".parse::<ThresholdSpec>().is_err());
    }

    #[test]
    fn redaction_masks_query_strings_and_api_keys() {
        assert_eq!(
            redact_url("https://devnet.helius-rpc.com/?api-key=secret"),
            "https://devnet.helius-rpc.com"
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
    fn url_display_removes_credentials_and_preserves_the_endpoint() {
        for input in [
            "https://alice:secret@rpc.example.com:8443/",
            "https://rpc.example.com:8443/v2/secret",
            "https://rpc.example.com:8443/?token=secret",
            "https://rpc.example.com:8443?token=secret",
            "https://rpc.example.com:8443/#secret",
        ] {
            assert_eq!(redact_url(input), "https://rpc.example.com:8443");
        }
        assert_eq!(redact_url("http://[::1]:8899/token"), "http://[::1]:8899");
        assert_eq!(redact_url("invalid secret URL"), "invalid URL");
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
        let error = RingConfig::set_target(&path, Target::Devnet).expect_err("no target");
        assert!(error.to_string().ends_with("has no target line"), "{error}");
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
        assert!(expand_env("${RING_TEST_UNSET_KEY}")
            .expect_err("unset")
            .to_string()
            .starts_with("RING_TEST_UNSET_KEY is not set"));
        assert!(expand_env("${RING_TEST_KEY")
            .expect_err("unclosed")
            .to_string()
            .starts_with("unclosed placeholder"));
    }
}
