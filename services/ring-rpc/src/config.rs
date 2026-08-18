//! Runtime configuration. The auditor secret is read from a file, never from
//! an argument or the environment, so it does not land in a process listing.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, ViewingKey};

#[derive(Debug, Parser)]
#[command(
    name = "ring-rpc",
    about = "Ring RPC for a custom ring with an auditor"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serve decrypted ring transactions.
    Serve(ServeArgs),
    /// Create an auditor key. The secret stays in the file, the public key goes
    /// into the ring's `create_config`.
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
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

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Destination of the secret (64 hex characters, mode 0600). The SEC1
    /// compressed public key is written next to it as `<out>.pub`.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error("cannot read auditor key file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write auditor key file {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("auditor key file is not 64 hex characters")]
    Encoding,
    #[error("auditor key is not a valid P256 secret key: {0}")]
    Key(#[from] KeypairError),
}

/// Writes a fresh auditor key: the secret to `out` (mode 0600 on unix) and the
/// SEC1 compressed public key as hex to `<out>.pub`. Refuses to overwrite.
pub fn write_auditor_key(out: &Path) -> Result<ViewingKey, KeyFileError> {
    let key = ViewingKey::new();
    let secret_hex = Zeroizing::new(hex::encode(*key.secret_bytes()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_error = |source| KeyFileError::Write {
        path: out.to_path_buf(),
        source,
    };
    let mut file = options.open(out).map_err(write_error)?;
    std::io::Write::write_all(&mut file, secret_hex.as_bytes()).map_err(write_error)?;
    std::fs::write(public_key_path(out), hex::encode(key.pubkey().as_bytes())).map_err(
        |source| KeyFileError::Write {
            path: public_key_path(out),
            source,
        },
    )?;
    Ok(key)
}

/// `<out>.pub` next to the secret.
pub fn public_key_path(secret: &Path) -> PathBuf {
    let mut name = secret.file_name().unwrap_or_default().to_os_string();
    name.push(".pub");
    secret.with_file_name(name)
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
    fn keygen_writes_a_secret_the_loader_reads_and_a_matching_public_key() {
        let dir = std::env::temp_dir().join(format!("ring-rpc-keygen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let secret = dir.join("auditor.key");
        let key = write_auditor_key(&secret).expect("keygen");
        assert_eq!(
            load_auditor_key(&secret).expect("load").pubkey(),
            key.pubkey()
        );
        let public = std::fs::read_to_string(public_key_path(&secret)).expect("pub file");
        assert_eq!(hex::decode(public).expect("hex"), key.pubkey().as_bytes());
        assert!(matches!(
            write_auditor_key(&secret),
            Err(KeyFileError::Write { .. })
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn zero_scalar_is_rejected() {
        assert!(matches!(
            parse_auditor_key(&"00".repeat(32)),
            Err(KeyFileError::Key(_))
        ));
    }
}
