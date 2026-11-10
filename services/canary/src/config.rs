use std::{fmt, time::Duration};

use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_client::prover::tee::TeeNetwork;
use thiserror::Error;

const DEFAULT_INTERVAL_SECS: u64 = 60;
const DEFAULT_AMOUNT_LAMPORTS: u64 = 1_000;
const DEFAULT_TIMEOUT_SECS: u64 = 45;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{name} is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

fn invalid(name: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        name,
        reason: reason.into(),
    }
}

/// Everything the canary reads from its environment.
pub struct Config {
    pub rpc_url: String,
    pub api_url: String,
    pub api_key: String,
    pub tee_network: TeeNetwork,
    pub keypair: Keypair,
    pub interval: Duration,
    pub amount: u64,
    pub timeout: Duration,
    pub namespace: String,
}

// Hand-written so neither the API key nor the wallet secret reaches a log line.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("api_url", &self.api_url)
            .field("tee_network", &self.tee_network)
            .field("wallet", &self.keypair.pubkey())
            .field("interval", &self.interval)
            .field("amount", &self.amount)
            .field("timeout", &self.timeout)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let required = |name: &'static str| {
            get(name)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or(ConfigError::Missing(name))
        };
        let rpc_url = required("RPC_URL")?;
        if !(rpc_url.starts_with("https://") || rpc_url.starts_with("http://")) {
            return Err(invalid("RPC_URL", "expected an http(s) URL"));
        }
        let api_url = required("SPR_API_URL")?.trim_end_matches('/').to_string();
        if api_url.contains('?') {
            return Err(invalid(
                "SPR_API_URL",
                "must not carry a query; the key comes from SPR_API_KEY",
            ));
        }
        spr_client::check_service_url(&api_url, "SPR_API_URL")
            .map_err(|_| invalid("SPR_API_URL", "expected https, or http to loopback"))?;
        let api_key = required("SPR_API_KEY")?;
        if !api_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(invalid("SPR_API_KEY", "unexpected characters"));
        }
        let tee_network = match required("SPR_TEE_NETWORK")?.as_str() {
            "mainnet" => TeeNetwork::Mainnet,
            "devnet" => TeeNetwork::Devnet,
            _ => return Err(invalid("SPR_TEE_NETWORK", "expected mainnet or devnet")),
        };
        let keypair = parse_keypair(&required("CANARY_KEYPAIR")?)?;
        let positive = |name: &'static str, default: u64| match get(name) {
            None => Ok(default),
            Some(value) => match value.trim().parse::<u64>() {
                Ok(0) | Err(_) => Err(invalid(name, "expected a positive integer")),
                Ok(parsed) => Ok(parsed),
            },
        };
        let interval =
            Duration::from_secs(positive("CANARY_INTERVAL_SECS", DEFAULT_INTERVAL_SECS)?);
        let amount = positive("CANARY_AMOUNT_LAMPORTS", DEFAULT_AMOUNT_LAMPORTS)?;
        let timeout = Duration::from_secs(positive("CANARY_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?);
        let namespace = required("METRICS_NAMESPACE")?;
        Ok(Self {
            rpc_url,
            api_url,
            api_key,
            tee_network,
            keypair,
            interval,
            amount,
            timeout,
            namespace,
        })
    }

    /// The gatekeeper base with the key attached, as the indexer and prover clients expect it.
    pub fn gateway_url(&self) -> String {
        format!("{}?api-key={}", self.api_url, self.api_key)
    }

    /// Strings that must never appear in output.
    pub fn secrets(&self) -> Vec<String> {
        let mut secrets = vec![self.api_key.clone()];
        if let Some((_, query)) = self.rpc_url.split_once('?') {
            secrets.extend(
                query
                    .split('&')
                    .filter_map(|pair| pair.split_once('='))
                    .filter(|(key, value)| key.eq_ignore_ascii_case("api-key") && !value.is_empty())
                    .map(|(_, value)| value.to_string()),
            );
        }
        secrets
    }
}

/// A Solana keypair as `solana-keygen` writes it: 64 bytes, or a bare 32-byte secret.
fn parse_keypair(json: &str) -> Result<Keypair, ConfigError> {
    let name = "CANARY_KEYPAIR";
    let bytes: Vec<u8> =
        serde_json::from_str(json).map_err(|_| invalid(name, "expected a JSON byte array"))?;
    let secret: [u8; 32] = match bytes.len() {
        32 | 64 => bytes[..32].try_into().expect("length checked"),
        length => {
            return Err(invalid(
                name,
                format!("expected 32 or 64 bytes, got {length}"),
            ))
        }
    };
    let keypair = Keypair::new_from_array(secret);
    if bytes.len() == 64 && keypair.pubkey().to_bytes().as_slice() != &bytes[32..] {
        return Err(invalid(name, "secret does not match its public key"));
    }
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(overrides: &[(&str, Option<&str>)]) -> Result<Config, ConfigError> {
        let keypair = Keypair::new();
        let keypair_json = serde_json::to_string(&keypair.to_bytes().to_vec()).unwrap();
        let mut vars: HashMap<String, String> = [
            ("RPC_URL", "https://rpc.example/?api-key=rpc-secret"),
            ("SPR_API_URL", "https://gateway.example/v1/spr/"),
            ("SPR_API_KEY", "gate-secret"),
            ("SPR_TEE_NETWORK", "devnet"),
            ("CANARY_KEYPAIR", keypair_json.as_str()),
            ("METRICS_NAMESPACE", "test/canary"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (name, value) in overrides {
            match value {
                Some(value) => vars.insert(name.to_string(), value.to_string()),
                None => vars.remove(*name),
            };
        }
        Config::from_lookup(|name| vars.get(name).cloned())
    }

    #[test]
    fn defaults_apply_when_optional_vars_are_unset() {
        let config = env(&[]).unwrap();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.amount, 1_000);
        assert_eq!(config.timeout, Duration::from_secs(45));
        assert_eq!(config.tee_network, TeeNetwork::Devnet);
        assert_eq!(config.namespace, "test/canary");
    }

    #[test]
    fn optional_vars_override_defaults() {
        let config = env(&[
            ("CANARY_INTERVAL_SECS", Some("30")),
            ("CANARY_AMOUNT_LAMPORTS", Some("5000")),
            ("CANARY_TIMEOUT_SECS", Some("20")),
            ("SPR_TEE_NETWORK", Some("mainnet")),
        ])
        .unwrap();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.amount, 5_000);
        assert_eq!(config.timeout, Duration::from_secs(20));
        assert_eq!(config.tee_network, TeeNetwork::Mainnet);
    }

    #[test]
    fn gateway_url_carries_the_key_once() {
        let config = env(&[]).unwrap();
        assert_eq!(
            config.gateway_url(),
            "https://gateway.example/v1/spr?api-key=gate-secret"
        );
    }

    #[test]
    fn secrets_cover_both_keys() {
        let config = env(&[]).unwrap();
        assert_eq!(config.secrets(), vec!["gate-secret", "rpc-secret"]);
    }

    #[test]
    fn missing_required_vars_are_named() {
        for name in [
            "RPC_URL",
            "SPR_API_URL",
            "SPR_API_KEY",
            "SPR_TEE_NETWORK",
            "CANARY_KEYPAIR",
            "METRICS_NAMESPACE",
        ] {
            assert_eq!(
                env(&[(name, None)]).unwrap_err(),
                ConfigError::Missing(name)
            );
        }
    }

    #[test]
    fn invalid_values_are_rejected() {
        let cases: &[(&str, &str)] = &[
            ("SPR_TEE_NETWORK", "testnet"),
            ("SPR_API_URL", "http://gateway.example/v1/spr"),
            ("SPR_API_URL", "https://gateway.example/v1/spr?api-key=x"),
            ("SPR_API_KEY", "a&b"),
            ("RPC_URL", "ws://rpc.example"),
            ("CANARY_INTERVAL_SECS", "0"),
            ("CANARY_AMOUNT_LAMPORTS", "-1"),
            ("CANARY_TIMEOUT_SECS", "soon"),
            ("CANARY_KEYPAIR", "not json"),
            ("CANARY_KEYPAIR", "[1,2,3]"),
        ];
        for (name, value) in cases {
            let error = env(&[(name, Some(value))]).unwrap_err();
            assert!(
                matches!(error, ConfigError::Invalid { name: found, .. } if found == *name),
                "{name}={value}: {error}"
            );
        }
    }

    #[test]
    fn keypair_accepts_both_solana_forms_and_rejects_a_mismatch() {
        let keypair = Keypair::new();
        let full = serde_json::to_string(&keypair.to_bytes().to_vec()).unwrap();
        let bare = serde_json::to_string(&keypair.secret_bytes().to_vec()).unwrap();
        assert_eq!(parse_keypair(&full).unwrap().pubkey(), keypair.pubkey());
        assert_eq!(parse_keypair(&bare).unwrap().pubkey(), keypair.pubkey());
        let mut bad = keypair.to_bytes().to_vec();
        bad[63] ^= 0xff;
        assert!(parse_keypair(&serde_json::to_string(&bad).unwrap()).is_err());
    }

    #[test]
    fn errors_and_debug_never_print_secrets() {
        let error = env(&[("CANARY_KEYPAIR", Some("[9,9,9]"))]).unwrap_err();
        assert!(!error.to_string().contains("9,9"));
        let debug = format!("{:?}", env(&[]).unwrap());
        assert!(!debug.contains("gate-secret"));
        assert!(!debug.contains("rpc-secret"));
    }
}
