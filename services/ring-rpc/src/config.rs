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
use zolana_secret_file::{create_new, read_key32, Access, SecretFileError, Visibility};

use crate::{origins::OriginTransport, server::BindPolicy};

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
    /// Lowercase hex X25519 secret bytes.
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

    pub fn key_access(&self) -> Access {
        if self.allow_shared_key_file {
            Access::Shared
        } else {
            Access::OwnerOnly
        }
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.get())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_secs.get())
    }
}

pub struct RootSecret(Zeroizing<[u8; 32]>);

#[derive(Debug, Error)]
pub enum RootSecretError {
    #[error("root secret cannot be zero")]
    Zero,
    #[error(transparent)]
    File(#[from] SecretFileError),
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

pub fn read_root_secret(path: &Path, access: Access) -> Result<RootSecret, RootSecretError> {
    RootSecret::from_bytes(*read_key32(path, access)?)
}

pub fn write_root_secret(out: &Path) -> Result<(), RootSecretError> {
    let root = Zeroizing::new(hex::encode(RootSecret::random().as_bytes()));
    Ok(create_new(out, root.as_bytes(), Visibility::Secret)?)
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

    #[test]
    fn a_zero_or_malformed_root_secret_is_refused() {
        let dir = temp_dir("zero");
        let zero = dir.join("zero.key");
        create_new(&zero, "00".repeat(32).as_bytes(), Visibility::Secret).expect("zero");
        assert!(matches!(
            read_root_secret(&zero, Access::OwnerOnly),
            Err(RootSecretError::Zero)
        ));
        let upper = dir.join("upper.key");
        create_new(&upper, "AA".repeat(32).as_bytes(), Visibility::Secret).expect("upper");
        assert!(matches!(
            read_root_secret(&upper, Access::OwnerOnly),
            Err(RootSecretError::File(SecretFileError::Hex))
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn root_keygen_writes_a_nonzero_private_secret() {
        let dir = temp_dir("root-keygen");
        let secret = dir.join("nested/root.key");
        write_root_secret(&secret).expect("keygen");
        let root = read_root_secret(&secret, Access::OwnerOnly).expect("root");
        assert!(root.as_bytes().iter().any(|byte| *byte != 0));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
