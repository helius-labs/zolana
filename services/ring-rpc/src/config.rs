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
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};

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
    /// File holding one auditor P256 secret key as 64 hex characters. One ring
    /// per instance.
    #[arg(
        long,
        env = "RING_RPC_AUDITOR_KEY_FILE",
        conflicts_with = "root_secret_file",
        required_unless_present = "root_secret_file"
    )]
    pub auditor_key_file: Option<PathBuf>,
    /// File holding a 32-byte root secret as 64 hex characters. Every ring's
    /// auditor key is derived from it, so one instance serves any ring.
    #[arg(long, env = "RING_RPC_ROOT_SECRET_FILE")]
    pub root_secret_file: Option<PathBuf>,
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
    /// Accept a key or root secret file readable by other users (unix). Off by
    /// default so a misplaced key is noticed before the service answers.
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
    #[error("key file is not 64 hex characters")]
    Encoding,
    #[error("public key file is not 66 hex characters")]
    PubkeyEncoding,
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
    write_auditor_pubkey(&public_key_path(out), &key.pubkey())?;
    Ok(key)
}

/// `<out>.pub` next to the secret.
pub fn public_key_path(secret: &Path) -> PathBuf {
    let mut name = secret.file_name().unwrap_or_default().to_os_string();
    name.push(".pub");
    secret.with_file_name(name)
}

/// The SEC1 compressed auditor public key as hex, the format `read_auditor_pubkey`
/// and the ring CLI's `init` take.
pub fn write_auditor_pubkey(path: &Path, pubkey: &P256Pubkey) -> Result<(), KeyFileError> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|source| KeyFileError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(path, hex::encode(pubkey.as_bytes())).map_err(|source| KeyFileError::Write {
        path: path.to_path_buf(),
        source,
    })
}

pub fn read_auditor_pubkey(path: &Path) -> Result<P256Pubkey, KeyFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| KeyFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let bytes: [u8; 33] = hex::decode(text.trim())
        .map_err(|_| KeyFileError::PubkeyEncoding)?
        .try_into()
        .map_err(|_| KeyFileError::PubkeyEncoding)?;
    Ok(P256Pubkey::from_bytes(bytes)?)
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
    let secret = parse_hex32(text)?;
    Ok(ViewingKey::from_bytes(&secret)?)
}

/// Reads the 32-byte root secret every derived auditor key comes from.
pub fn load_root_secret(
    path: &Path,
    allow_shared: bool,
) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
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
    parse_hex32(&text)
}

fn parse_hex32(text: &str) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
    let decoded = Zeroizing::new(hex::decode(text.trim()).map_err(|_| KeyFileError::Encoding)?);
    let mut secret = Zeroizing::new([0u8; 32]);
    if decoded.len() != secret.len() {
        return Err(KeyFileError::Encoding);
    }
    secret.copy_from_slice(&decoded);
    Ok(secret)
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
        assert_eq!(
            read_auditor_pubkey(&public_key_path(&secret)).expect("pub file"),
            key.pubkey()
        );
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
