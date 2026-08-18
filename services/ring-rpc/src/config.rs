//! Runtime configuration. The auditor secret is read from a file, never from
//! an argument or the environment, so it does not land in a process listing.

use std::path::{Path, PathBuf};

use clap::Parser;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, ViewingKey};

#[derive(Debug, Parser)]
#[command(
    name = "ring-rpc",
    about = "Ring RPC for a custom ring with an auditor"
)]
pub struct Args {
    #[arg(long, env = "RING_RPC_PORT", default_value_t = 8785)]
    pub port: u16,
    /// Photon indexer that indexes the ring's transactions.
    #[arg(
        long,
        env = "RING_RPC_INDEXER_URL",
        default_value = "http://127.0.0.1:8784"
    )]
    pub indexer_url: String,
    /// Solana RPC, read once at startup for the SPL asset registry.
    #[arg(
        long,
        env = "RING_RPC_SOLANA_RPC_URL",
        default_value = "http://127.0.0.1:8899"
    )]
    pub rpc_url: String,
    /// File holding the auditor P256 secret key as 64 hex characters.
    #[arg(long, env = "RING_RPC_AUDITOR_KEY_FILE")]
    pub auditor_key_file: PathBuf,
}

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error("cannot read auditor key file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("auditor key file is not 64 hex characters")]
    Encoding,
    #[error("auditor key is not a valid P256 secret key: {0}")]
    Key(#[from] KeypairError),
}

/// Reads the auditor viewing key. Intermediate buffers are zeroized.
pub fn load_auditor_key(path: &Path) -> Result<ViewingKey, KeyFileError> {
    let text =
        Zeroizing::new(
            std::fs::read_to_string(path).map_err(|source| KeyFileError::Read {
                path: path.to_path_buf(),
                source,
            })?,
        );
    parse_auditor_key(&text)
}

pub fn parse_auditor_key(text: &str) -> Result<ViewingKey, KeyFileError> {
    let decoded = Zeroizing::new(hex::decode(text.trim()).map_err(|_| KeyFileError::Encoding)?);
    let mut secret = Zeroizing::new([0u8; 32]);
    if decoded.len() != secret.len() {
        return Err(KeyFileError::Encoding);
    }
    secret.copy_from_slice(&decoded);
    Ok(ViewingKey::from_bytes(&secret)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_key_round_trips_with_surrounding_whitespace() {
        let key = ViewingKey::new();
        let text = format!("  {}\n", hex::encode(*key.secret_bytes()));
        let parsed = parse_auditor_key(&text).expect("parse key");
        assert_eq!(parsed.pubkey(), key.pubkey());
    }

    #[test]
    fn short_and_non_hex_inputs_are_rejected() {
        assert!(matches!(
            parse_auditor_key("abcd"),
            Err(KeyFileError::Encoding)
        ));
        assert!(matches!(
            parse_auditor_key(&"zz".repeat(32)),
            Err(KeyFileError::Encoding)
        ));
    }

    #[test]
    fn zero_scalar_is_rejected() {
        assert!(matches!(
            parse_auditor_key(&"00".repeat(32)),
            Err(KeyFileError::Key(_))
        ));
    }
}
