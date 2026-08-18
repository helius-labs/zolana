//! Runtime configuration. The auditor secret is read from a file, never from
//! an argument or the environment, so it does not land in a process listing.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

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
    /// Serve decrypted ring transactions and the auditor page.
    Serve(ServeArgs),
    /// Create an auditor key. The secret stays in the file, the public key goes
    /// into the ring's `create_config`.
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Interface to listen on. Loopback by default; the auditor key opens every
    /// transaction of the ring, so exposing the port is a deliberate step.
    #[arg(long, env = "RING_RPC_BIND", default_value = "127.0.0.1")]
    pub bind: IpAddr,
    #[arg(long, env = "RING_RPC_PORT", default_value_t = 8785)]
    pub port: u16,
    /// Photon indexer that indexes the ring's transactions.
    #[arg(
        long,
        env = "RING_RPC_INDEXER_URL",
        default_value = "http://127.0.0.1:8784"
    )]
    pub indexer_url: String,
    /// Solana RPC, for the SPL asset registry at startup and transaction signers.
    #[arg(
        long,
        env = "RING_RPC_SOLANA_RPC_URL",
        default_value = "http://127.0.0.1:8899"
    )]
    pub rpc_url: String,
    /// File holding the auditor P256 secret key as 64 hex characters.
    #[arg(long, env = "RING_RPC_AUDITOR_KEY_FILE")]
    pub auditor_key_file: PathBuf,
    /// Browser origins allowed to call the JSON-RPC methods. The built-in page
    /// is same-origin and needs none; a UI hosted elsewhere names its origin here.
    #[arg(
        long = "allow-origin",
        env = "RING_RPC_ALLOW_ORIGINS",
        value_delimiter = ','
    )]
    pub allow_origins: Vec<String>,
    /// Concurrent connections the server accepts.
    #[arg(long, env = "RING_RPC_MAX_CONNECTIONS", default_value_t = 256)]
    pub max_connections: u32,
    /// Upper bound for one request, including its indexer and RPC reads.
    #[arg(long, env = "RING_RPC_REQUEST_TIMEOUT_SECS", default_value_t = 30)]
    pub request_timeout_secs: u64,
    /// Upper bound for one upstream call to the indexer or the Solana RPC.
    #[arg(long, env = "RING_RPC_UPSTREAM_TIMEOUT_SECS", default_value_t = 10)]
    pub upstream_timeout_secs: u64,
    /// Accept an auditor key file readable by other users (unix). Off by default
    /// so a misplaced key is noticed before the service answers.
    #[arg(long, env = "RING_RPC_ALLOW_SHARED_KEY_FILE")]
    pub allow_shared_key_file: bool,
}

impl ServeArgs {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_secs)
    }
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
    #[error("auditor key file {path} is readable by other users (mode {mode:o}); chmod 600 it or pass --allow-shared-key-file")]
    Shared { path: PathBuf, mode: u32 },
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

/// Reads the auditor viewing key. Intermediate buffers are zeroized. Unless
/// `allow_shared` is set, a file with group or world permission bits is refused.
pub fn load_auditor_key(path: &Path, allow_shared: bool) -> Result<ViewingKey, KeyFileError> {
    if !allow_shared {
        check_private(path)?;
    }
    let text =
        Zeroizing::new(
            std::fs::read_to_string(path).map_err(|source| KeyFileError::Read {
                path: path.to_path_buf(),
                source,
            })?,
        );
    parse_auditor_key(&text)
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), KeyFileError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|source| KeyFileError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyFileError::Shared {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), KeyFileError> {
    Ok(())
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

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

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
        let dir = temp_dir("keygen");
        let secret = dir.join("auditor.key");
        let key = write_auditor_key(&secret).expect("keygen");
        assert_eq!(
            load_auditor_key(&secret, false).expect("load").pubkey(),
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

    #[cfg(unix)]
    #[test]
    fn a_shared_key_file_is_refused_unless_allowed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("shared");
        let secret = dir.join("auditor.key");
        write_auditor_key(&secret).expect("keygen");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            load_auditor_key(&secret, false),
            Err(KeyFileError::Shared { mode: 0o644, .. })
        ));
        assert!(load_auditor_key(&secret, true).is_ok());
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
