//! Every command reads `ring.toml`, the answers the wizard recorded.

pub mod authority;
pub mod config;
pub mod deploy;
pub mod error;
pub mod fund;
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
use zolana_client::{ClientError, ProverClient, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_keypair::ShieldedAddress;

pub use crate::{
    config::{ConfigError, RingConfig, Target, RING_TOML},
    error::CliError,
    fund::FundError,
    init::InitError,
    ring_rpc::{RingRpcClient, Trust},
};

/// What localnet tops the authority up to.
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
    /// Deposit an amount and send all of it to a shielded address inside the ring.
    Transfer(TransferArgs),
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
    /// Pin the key in `keys/` even though the ring RPC is not on this machine.
    /// Only a ring RPC holding that key can ever open the ring.
    #[arg(long)]
    pub local_auditor: bool,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives, deposited twice by the authority.
    #[arg(long, default_value_t = 100_000_000)]
    pub amount: u64,
}

#[derive(Debug, Args)]
pub struct TransferArgs {
    /// The recipient's base58 shielded address, `signing_pk || nullifier_pk || viewing_pk`.
    pub to: ShieldedAddress,
    /// Lamports the recipient receives, deposited by the authority.
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
    Fund(#[from] FundError),
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

    /// For a step that only pays fees and small rent.
    pub fn funded_authority(&mut self) -> Result<Keypair, ContextError> {
        self.authority_funded_for(fund::MIN_AUTHORITY_BALANCE)
    }

    pub fn authority_funded_for(&mut self, required: u64) -> Result<Keypair, ContextError> {
        let authority = self.config.authority()?;
        self.fund_authority(&authority, required)?;
        Ok(authority)
    }

    /// Localnet airdrops what the step spends, devnet waits at the faucet.
    pub fn fund_authority(
        &mut self,
        authority: &Keypair,
        required: u64,
    ) -> Result<(), ContextError> {
        match self.config.target {
            Target::Localnet => {
                let balance = self.rpc.get_balance(authority.pubkey())?;
                if balance < required.max(LOCALNET_AUTHORITY_BALANCE / 2) {
                    self.rpc.airdrop(
                        &authority.pubkey(),
                        required.max(LOCALNET_AUTHORITY_BALANCE),
                    )?;
                }
            }
            Target::Devnet => fund::wait_for_balance(&self.rpc, authority.pubkey(), required)?,
        }
        Ok(())
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
        Command::Transfer(args) => Ok(transact::run_transfer(&mut ctx, args)?),
        Command::RpcCheck => Ok(ring_rpc::run_check(&ctx)?),
        Command::Authority(command) => Ok(authority::run(&ctx, command)?),
        Command::Reader(command) => Ok(reader::run(&mut ctx, command)?),
    }
}
