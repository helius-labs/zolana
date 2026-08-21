//! Every command reads `ring.toml`, the answers the wizard recorded.

pub mod authority;
pub mod config;
pub mod deploy;
pub mod error;
pub mod init;
pub mod reader;
pub mod ring_rpc;
pub mod status;
pub mod step;
pub mod transact;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use custom_ring_sdk::{CustomRing, ReaderKey};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ProverClient, SolanaRpc, ZolanaIndexer};

pub use crate::{
    config::{ConfigError, RingConfig, Target, RING_TOML},
    error::CliError,
    init::InitError,
    ring_rpc::{RingRpcClient, Trust},
};

const LOCALNET_AUTHORITY_BALANCE: u64 = 100_000_000_000;

#[derive(Debug, Parser)]
#[command(
    name = "custom-ring",
    about = "Operate a custom ring generated from the template"
)]
pub struct Cli {
    /// Path to ring.toml.
    #[arg(long, default_value = RING_TOML, global = true)]
    pub config: PathBuf,
    /// Cluster for one command instead of the one ring.toml records.
    #[arg(long, global = true, env = "RING_TARGET")]
    pub target: Option<Target>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Recorded answers and on-chain state.
    Status,
    /// Record the cluster the ring acts on in ring.toml.
    Target { target: Target },
    /// Print one service URL of the active target.
    Url { service: Service },
    /// Deploy the program under the authority, or upgrade it in place.
    Deploy(DeployArgs),
    /// Create the config with the auditor key and register the ring with SPP.
    Init(InitArgs),
    /// Two ring deposits and one audited transfer, read back from the ring RPC.
    Transact(TransactArgs),
    /// Confirm the ring RPC in `ring.toml` is up and holds the ring's auditor key.
    RpcCheck,
    /// Transfer or renounce the program's upgrade authority.
    #[command(subcommand)]
    Authority(AuthorityCommand),
    /// Grant or revoke reads on the ring RPC.
    #[command(subcommand)]
    Reader(ReaderCommand),
}

#[derive(Debug, Subcommand)]
pub enum ReaderCommand {
    /// A base58 Solana key or the 66-hex P-256 key of a passkey.
    Grant { reader: ReaderKey },
    /// Close the reader's record, the rent returns to the authority.
    Revoke { reader: ReaderKey },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Service {
    Rpc,
    Indexer,
    Prover,
    RingRpc,
}

#[derive(Debug, Subcommand)]
pub enum AuthorityCommand {
    /// Hand the program to another key, then update `authority_keypair` in ring.toml.
    Transfer { new_authority: Address },
    /// Make the program immutable, irreversible.
    Renounce {
        /// Confirms the irreversible step.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// Defaults to `target/deploy/<name>_program.so`.
    #[arg(long)]
    pub program_so: Option<PathBuf>,
    #[arg(long, default_value = "keys/program-keypair.json")]
    pub program_keypair: PathBuf,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Hex SEC1 compressed auditor key, created by the ring RPC and written here when absent.
    #[arg(long, default_value = "keys/auditor.key.pub")]
    pub auditor_pubkey_file: PathBuf,
    /// Accept the ring RPC's auditor key without a pinned service key in ring.toml.
    #[arg(long)]
    pub trust_ring_rpc: bool,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives, deposited twice by the authority.
    #[arg(long, default_value_t = 100_000_000)]
    pub amount: u64,
}

pub struct Context {
    pub config_path: PathBuf,
    pub config: RingConfig,
    pub ring: CustomRing,
    pub rpc: SolanaRpc,
}

#[derive(Debug, Error)]
pub enum ContextError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Client(Box<ClientError>),
}

impl From<ClientError> for ContextError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

impl Context {
    pub fn load(config_path: PathBuf, config: RingConfig) -> Self {
        let ring = CustomRing::new(config.program_id);
        let rpc = SolanaRpc::new(config.urls().rpc.clone());
        Self {
            config_path,
            config,
            ring,
            rpc,
        }
    }

    /// Airdrops on localnet when below half of `LOCALNET_AUTHORITY_BALANCE`.
    pub fn funded_authority(&mut self) -> Result<Keypair, ContextError> {
        let authority = self.config.authority()?;
        if self.config.target == Target::Localnet {
            let balance = self
                .rpc
                .client()
                .get_balance(&authority.pubkey())
                .map_err(|error| ClientError::Rpc(error.to_string()))?;
            if balance < LOCALNET_AUTHORITY_BALANCE / 2 {
                self.rpc
                    .airdrop(&authority.pubkey(), LOCALNET_AUTHORITY_BALANCE)?;
            }
        }
        Ok(authority)
    }

    pub fn ring_rpc(&self) -> RingRpcClient {
        RingRpcClient::new(&self.config.urls().ring_rpc)
    }

    pub fn indexer(&self) -> ZolanaIndexer {
        ZolanaIndexer::new(&self.config.urls().indexer)
    }

    pub fn prover(&self) -> ProverClient {
        ProverClient::new(self.config.urls().prover.clone())
    }

    /// `unpinned` applies only when ring.toml pins no service key.
    pub fn trust(&self, unpinned: Trust) -> Result<Trust, ConfigError> {
        match self.config.urls().ring_rpc_pubkey.as_deref() {
            Some(key) => key
                .parse()
                .map(Trust::Pinned)
                .map_err(|_| ConfigError::RingRpcPubkey {
                    key: key.to_owned(),
                }),
            None => Ok(unpinned),
        }
    }
}

pub fn parse_and_run() -> Result<(), CliError> {
    run(Cli::parse())
}

/// `Target` and `Url` finish before any RPC client exists.
pub fn run(cli: Cli) -> Result<(), CliError> {
    let mut config = RingConfig::load(&cli.config)?;
    if let Command::Target { target } = cli.command {
        RingConfig::set_target(&cli.config, target)?;
        println!("target      {}", target.as_str());
        return Ok(());
    }
    if let Some(target) = cli.target {
        config.target = target;
    }
    if let Command::Url { service } = cli.command {
        let urls = config.urls();
        println!(
            "{}",
            match service {
                Service::Rpc => &urls.rpc,
                Service::Indexer => &urls.indexer,
                Service::Prover => &urls.prover,
                Service::RingRpc => &urls.ring_rpc,
            }
        );
        return Ok(());
    }
    let mut ctx = Context::load(cli.config, config);
    match cli.command {
        Command::Target { .. } | Command::Url { .. } => Ok(()),
        Command::Status => {
            status::run(&ctx);
            Ok(())
        }
        Command::Deploy(args) => Ok(deploy::run(&mut ctx, args)?),
        Command::Init(args) => Ok(init::run(&mut ctx, args)?),
        Command::Transact(args) => Ok(transact::run(&mut ctx, args)?),
        Command::RpcCheck => Ok(ring_rpc::run_check(&ctx)?),
        Command::Authority(command) => Ok(authority::run(&ctx, command)?),
        Command::Reader(command) => Ok(reader::run(&mut ctx, command)?),
    }
}
