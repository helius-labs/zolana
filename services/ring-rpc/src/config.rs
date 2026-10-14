use std::{
    net::IpAddr,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use rand::RngCore;
use solana_address::Address;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, P256Pubkey, ViewingKey};
pub use zolana_secret_file::Access as KeyAccess;
use zolana_secret_file::{
    create_new, create_pair, read_hex32, read_private, SecretFileError, Visibility,
};

use crate::{origins::OriginTransport, server::BindPolicy};

const KEY_HEX_LEN: u64 = 64;

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
    Serve(ServeArgs),
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long, env = "RING_RPC_BIND", default_value = "127.0.0.1")]
    pub bind: IpAddr,
    #[arg(long, env = "RING_RPC_PORT", default_value_t = 8785)]
    pub port: u16,
    #[arg(
        long,
        env = "RING_RPC_INDEXER_URL",
        default_value = "http://127.0.0.1:8784"
    )]
    pub indexer_url: String,
    #[arg(
        long,
        env = "RING_RPC_SOLANA_RPC_URL",
        default_value = "http://127.0.0.1:8899"
    )]
    pub rpc_url: String,
    /// Lowercase hex P256 scalar.
    #[arg(
        long,
        env = "RING_RPC_AUDITOR_KEY_FILE",
        conflicts_with = "root_secret_file",
        required_unless_present = "root_secret_file"
    )]
    pub auditor_key_file: Option<PathBuf>,
    #[arg(long, env = "RING_RPC_RING_PROGRAM_ID", requires = "auditor_key_file")]
    pub ring_program_id: Option<Address>,
    /// Lowercase hex root secret.
    #[arg(long, env = "RING_RPC_ROOT_SECRET_FILE")]
    pub root_secret_file: Option<PathBuf>,
    #[arg(
        long = "allow-origin",
        env = "RING_RPC_ALLOW_ORIGINS",
        value_delimiter = ','
    )]
    pub allow_origins: Vec<String>,
    #[arg(long, env = "RING_RPC_WEBAUTHN_RP_ID")]
    pub webauthn_rp_id: Option<String>,
    #[arg(long, env = "RING_RPC_MAX_CONNECTIONS", default_value = "256")]
    pub max_connections: NonZeroU32,
    #[arg(long, env = "RING_RPC_REQUEST_TIMEOUT_SECS", default_value = "30")]
    pub request_timeout_secs: NonZeroU64,
    #[arg(long, env = "RING_RPC_UPSTREAM_TIMEOUT_SECS", default_value = "10")]
    pub upstream_timeout_secs: NonZeroU64,
    #[arg(long, env = "RING_RPC_ALLOW_SHARED_KEY_FILE")]
    pub allow_shared_key_file: bool,
    /// Serve plain HTTP on a public address and accept plain HTTP origins, test deployments only.
    #[arg(long, env = "RING_RPC_INSECURE_PUBLIC_BIND")]
    pub insecure_public_bind: bool,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, value_enum, default_value_t = KeyKind::Auditor)]
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KeyKind {
    Auditor,
    Root,
}

impl ServeArgs {
    pub fn origin_transport(&self) -> OriginTransport {
        if self.insecure_public_bind {
            OriginTransport::InsecureHttp
        } else {
            OriginTransport::SecureOnly
        }
    }

    pub fn bind_policy(&self) -> BindPolicy {
        if self.insecure_public_bind {
            BindPolicy::InsecurePublic
        } else {
            BindPolicy::LoopbackOnly
        }
    }

    pub fn key_access(&self) -> KeyAccess {
        if self.allow_shared_key_file {
            KeyAccess::Shared
        } else {
            KeyAccess::OwnerOnly
        }
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.get())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_secs.get())
    }
}

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error(transparent)]
    File(#[from] SecretFileError),
    #[error("public key file is not 66 hex characters")]
    PubkeyEncoding,
    #[error("key path must name a file")]
    InvalidPath,
    #[error("auditor key is not a valid P256 secret key because {0}")]
    Key(#[from] KeypairError),
    #[error(transparent)]
    Root(#[from] RootSecretError),
}

#[must_use]
pub struct KeyFile<'a> {
    pub path: &'a Path,
    pub access: KeyAccess,
}

pub struct RootSecret(Zeroizing<[u8; 32]>);

#[derive(Debug, Error)]
pub enum RootSecretError {
    #[error("root secret cannot be zero")]
    Zero,
}

impl RootSecret {
    pub fn random() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            if let Ok(root) = Self::from_bytes(bytes) {
                return root;
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RootSecretError> {
        if bytes == [0; 32] {
            return Err(RootSecretError::Zero);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl KeyFile<'_> {
    pub fn auditor_key(self) -> Result<ViewingKey, KeyFileError> {
        let secret = self.secret()?;
        Ok(ViewingKey::from_bytes(&secret)?)
    }

    pub fn root_secret(self) -> Result<RootSecret, KeyFileError> {
        Ok(RootSecret::from_bytes(*self.secret()?)?)
    }

    fn secret(self) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
        Ok(read_hex32(&read_private(
            self.path,
            self.access,
            KEY_HEX_LEN,
        )?)?)
    }
}

/// Neither file remains when either cannot be written.
pub fn write_auditor_key(out: &Path) -> Result<ViewingKey, KeyFileError> {
    let public_path = public_key_path(out)?;
    let key = ViewingKey::new();
    let secret = Zeroizing::new(hex::encode(*key.secret_bytes()));
    let public = hex::encode(key.pubkey().as_bytes());
    create_pair((out, secret.as_bytes()), (&public_path, public.as_bytes()))?;
    Ok(key)
}

pub fn write_root_secret(out: &Path) -> Result<(), KeyFileError> {
    let root = Zeroizing::new(hex::encode(RootSecret::random().as_bytes()));
    Ok(create_new(out, root.as_bytes(), Visibility::Secret)?)
}

pub fn write_auditor_pubkey(path: &Path, pubkey: &P256Pubkey) -> Result<(), KeyFileError> {
    let public = hex::encode(pubkey.as_bytes());
    Ok(create_new(path, public.as_bytes(), Visibility::Public)?)
}

pub fn read_auditor_pubkey(path: &Path) -> Result<P256Pubkey, KeyFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| SecretFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = hex::decode(text.trim())
        .ok()
        .and_then(|bytes| <[u8; 33]>::try_from(bytes).ok())
        .ok_or(KeyFileError::PubkeyEncoding)?;
    Ok(P256Pubkey::from_bytes(bytes)?)
}

pub fn public_key_path(secret: &Path) -> Result<PathBuf, KeyFileError> {
    let mut name = secret
        .file_name()
        .ok_or(KeyFileError::InvalidPath)?
        .to_os_string();
    name.push(".pub");
    Ok(secret.with_file_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn key_file(path: &Path) -> KeyFile<'_> {
        KeyFile {
            path,
            access: KeyAccess::OwnerOnly,
        }
    }

    #[test]
    fn keygen_writes_a_secret_the_loader_reads_and_a_matching_public_key() {
        let dir = temp_dir("keygen");
        let secret = dir.join("auditor.key");
        let key = write_auditor_key(&secret).expect("keygen");
        assert_eq!(
            key_file(&secret).auditor_key().expect("load").pubkey(),
            key.pubkey()
        );
        let public_path = public_key_path(&secret).expect("public path");
        assert_eq!(
            std::fs::read_to_string(&public_path).expect("pub file"),
            hex::encode(key.pubkey().as_bytes())
        );
        assert_eq!(
            read_auditor_pubkey(&public_path).expect("pubkey"),
            key.pubkey()
        );
        assert!(matches!(
            write_auditor_key(&secret),
            Err(KeyFileError::File(SecretFileError::Write { .. }))
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn public_key_files_round_trip_and_reject_other_lengths() {
        let dir = temp_dir("pubkey");
        let path = dir.join("nested").join("auditor.key.pub");
        let key = ViewingKey::new();
        write_auditor_pubkey(&path, &key.pubkey()).expect("write");
        assert_eq!(read_auditor_pubkey(&path).expect("read"), key.pubkey());
        let short = dir.join("short.pub");
        std::fs::write(&short, "02ab").expect("short");
        assert!(matches!(
            read_auditor_pubkey(&short),
            Err(KeyFileError::PubkeyEncoding)
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn a_zero_or_malformed_secret_is_refused() {
        let dir = temp_dir("zero");
        let zero = dir.join("zero.key");
        create_new(&zero, "00".repeat(32).as_bytes(), Visibility::Secret).expect("zero");
        assert!(matches!(
            key_file(&zero).auditor_key(),
            Err(KeyFileError::Key(_))
        ));
        assert!(matches!(
            key_file(&zero).root_secret(),
            Err(KeyFileError::Root(RootSecretError::Zero))
        ));
        let upper = dir.join("upper.key");
        create_new(&upper, "AA".repeat(32).as_bytes(), Visibility::Secret).expect("upper");
        assert!(matches!(
            key_file(&upper).root_secret(),
            Err(KeyFileError::File(SecretFileError::Hex))
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn root_keygen_writes_a_nonzero_private_secret() {
        let dir = temp_dir("root-keygen");
        let secret = dir.join("nested/root.key");
        write_root_secret(&secret).expect("keygen");
        let root = key_file(&secret).root_secret().expect("root");
        assert!(root.as_bytes().iter().any(|byte| *byte != 0));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
