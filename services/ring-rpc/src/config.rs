use std::{
    net::IpAddr,
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use solana_address::Address;
pub use zolana_ring_client::keyfile::{
    public_key_path, read_auditor_pubkey, write_auditor_key, write_auditor_pubkey,
    write_root_secret, FileMode, KeyAccess, KeyFile, KeyFileError, RootSecret, RootSecretError,
};

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

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.get())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_secs.get())
    }
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
