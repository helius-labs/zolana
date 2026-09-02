//! Every command but `new` reads `ring.toml`, the answers `new` recorded.

pub mod authority;
pub mod config;
pub mod deploy;
pub mod error;
pub mod file;
pub mod fund;
pub mod init;
pub mod keys;
pub mod list;
pub mod localnet;
pub mod new;
pub mod pipeline;
pub mod probe;
pub mod reader;
pub mod release;
pub mod ring_rpc;
pub mod status;
pub mod step;
pub mod tool;
pub mod transact;

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use custom_ring_sdk::{CustomRing, ReaderKey};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::str::FromStr;
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

pub const PROGRAM_KEYPAIR_FILE: &str = "keys/program-keypair.json";
pub const AUDITOR_KEY_FILE: &str = "keys/auditor.key";
pub const AUDITOR_PUBKEY_FILE: &str = "keys/auditor.key.pub";
pub const SENDER_KEYPAIR_FILE: &str = "keys/sender-keypair.json";
pub const DEFAULT_TRANSACT_AMOUNT: u64 = 100_000_000;

#[derive(Debug, Parser)]
#[command(name = "zolana-ring", about = "Operate a custom ring")]
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
    /// Create the ring directory with ring.toml and the program keypair.
    New(NewArgs),
    /// Recorded answers and on-chain state.
    Status,
    /// Record the cluster the ring acts on in ring.toml.
    Target { target: Target },
    /// Print one service URL of the active target.
    Url { service: Service },
    /// Record devnet in ring.toml and probe the deployed services.
    Devnet,
    /// Record localnet in ring.toml and start the validator, Photon, the prover and the ring rpc.
    Localnet(LocalnetArgs),
    /// Deploy the released program under the authority, or upgrade it in place.
    Deploy(DeployArgs),
    /// Create the config with the auditor key and register the ring with SPP.
    Init(InitArgs),
    /// Deploy, init, check the ring rpc, grant the authority and transact.
    Pipeline(DeployArgs),
    /// Two ring deposits and one custom-ring transfer, read back from the ring RPC.
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
    /// Read and mutate the ring's policy entries.
    #[command(subcommand)]
    List(ListCommand),
    /// Print the local auditor key's public key, or create the key file.
    AuditorKey(AuditorKeyArgs),
}

#[derive(Debug, Subcommand)]
pub enum ListCommand {
    /// Create the policy config, pinning the compiled table and the tree.
    Init { entries_tree: Address },
    /// Claim or reactivate the member's entry of the list.
    Add {
        #[arg(value_enum)]
        list_id: ListIdArg,
        member: Address,
    },
    /// Clear the member's entry, leaving the address claimed.
    Clear {
        #[arg(value_enum)]
        list_id: ListIdArg,
        member: Address,
    },
    /// Print the member's live entry.
    Show {
        #[arg(value_enum)]
        list_id: ListIdArg,
        member: Address,
    },
    /// Point the list at the ring's own namespace or a curator ring's.
    SetSource {
        #[arg(value_enum)]
        list_id: ListIdArg,
        /// Curator ring program id.
        #[arg(long, conflicts_with = "own", required_unless_present = "own")]
        curator: Option<Address>,
        #[arg(long)]
        own: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ListIdArg {
    Allow,
    Block,
    Frozen,
}

impl From<ListIdArg> for zolana_ring_policy::ListId {
    fn from(list_id: ListIdArg) -> Self {
        match list_id {
            ListIdArg::Allow => Self::Allow,
            ListIdArg::Block => Self::Block,
            ListIdArg::Frozen => Self::Frozen,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ReaderCommand {
    /// A base58 Solana key or the 66-hex P-256 key of a passkey.
    Grant { reader: ReaderKey },
    /// Close the reader's entry, the rent returns to the authority.
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
    /// Hand the program to another key, then set `upgrade_authority_keypair`.
    Transfer {
        new_authority: Address,
        /// Confirms the new key, nobody else can hand the program back.
        #[arg(long)]
        yes: bool,
    },
    /// Hand the ring config authority to another keypair, both keys sign.
    TransferConfig { new_authority_keypair: PathBuf },
    /// Stop every deposit, transfer and merge of the ring.
    Pause,
    /// Open the ring again after a pause.
    Resume,
    /// Make the program immutable, irreversible.
    Renounce {
        /// Confirms the irreversible step.
        #[arg(long)]
        yes: bool,
        /// The binary the deployment must match, the released ring program by default.
        #[arg(long)]
        program_so: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct NewArgs {
    /// Ring name in kebab-case, also the directory name.
    pub name: String,
    /// Parent directory the ring is created in.
    #[arg(long, default_value = ".")]
    pub dest: PathBuf,
    /// Answer every question with its default.
    #[arg(long)]
    pub silent: bool,
    /// Recorded in ring.toml, `~` stays literal for other machines.
    #[arg(long, default_value = new::DEFAULT_AUTHORITY_KEYPAIR)]
    pub authority_keypair: String,
}

#[derive(Debug, Args)]
pub struct LocalnetArgs {
    /// Record the target and print the URLs, start nothing.
    #[arg(long)]
    pub no_start: bool,
}

#[derive(Debug, Args)]
pub struct AuditorKeyArgs {
    /// The auditor secret a local ring rpc serves, its `.pub` sits beside it.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub key_file: PathBuf,
    /// Create the key and its `.pub` instead of reading it, refuses to overwrite.
    #[arg(long)]
    pub create: bool,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// A local binary instead of the released ring program.
    #[arg(long)]
    pub program_so: Option<PathBuf>,
    #[arg(long, default_value = PROGRAM_KEYPAIR_FILE)]
    pub program_keypair: PathBuf,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Hex SEC1 compressed auditor key, created by the ring RPC and written here when absent.
    #[arg(long, default_value = AUDITOR_PUBKEY_FILE)]
    pub auditor_pubkey_file: PathBuf,
    /// Accept the ring RPC's auditor key without a pinned service key in ring.toml.
    #[arg(long)]
    pub trust_ring_rpc: bool,
    /// Pin the key in `keys/` even though the ring RPC is not on this machine.
    /// Only a ring RPC holding that key can ever open the ring.
    #[arg(long)]
    pub local_auditor: bool,
    /// The tree the ring's policy entries live in.
    #[arg(long, default_value = zolana_interface::DEFAULT_TREE_ADDRESS)]
    pub entries_tree: Address,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives, deposited twice by the authority.
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
}

#[derive(Debug, Args)]
pub struct TransferArgs {
    /// The recipient's base58 shielded address, `signing_pk || nullifier_pk || viewing_pk`.
    pub to: ShieldedAddress,
    /// Lamports the recipient receives, deposited by the authority.
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
}

// The pipeline runs each step with the answers its command defaults to.

impl Default for DeployArgs {
    fn default() -> Self {
        Self {
            program_so: None,
            program_keypair: PathBuf::from(PROGRAM_KEYPAIR_FILE),
        }
    }
}

impl Default for InitArgs {
    fn default() -> Self {
        Self {
            auditor_pubkey_file: PathBuf::from(AUDITOR_PUBKEY_FILE),
            trust_ring_rpc: false,
            local_auditor: false,
            entries_tree: Address::from_str(zolana_interface::DEFAULT_TREE_ADDRESS)
                .expect("default tree address is valid"),
        }
    }
}

impl Default for TransactArgs {
    fn default() -> Self {
        Self {
            amount: DEFAULT_TRANSACT_AMOUNT,
        }
    }
}

pub struct Context {
    pub config_path: PathBuf,
    pub project_root: ProjectRoot,
    pub config: RingConfig,
    pub ring: CustomRing,
    pub rpc: SolanaRpc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectRoot(PathBuf);

#[derive(Debug, Error)]
pub enum ContextError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Fund(#[from] FundError),
    #[error(transparent)]
    Client(Box<ClientError>),
}

impl Context {
    pub fn load(config_path: PathBuf, mut config: RingConfig) -> Self {
        let project_root = ProjectRoot::for_config(&config_path);
        config.resolve_keypair_paths(&project_root);
        let ring = CustomRing::new(config.program_id);
        let rpc = SolanaRpc::new(config.urls().rpc.clone());
        Self {
            config_path,
            project_root,
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
        let authority = self.config.config_authority()?;
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

    /// Pins a ring rpc authority signature to the cluster the configured RPC serves.
    pub fn genesis_hash(&self) -> Result<[u8; 32], ContextError> {
        Ok(self.rpc.genesis_hash()?)
    }

    pub fn project_path(&self, path: &Path) -> PathBuf {
        self.project_root.resolve(path)
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

impl ProjectRoot {
    pub fn for_config(config_path: &Path) -> Self {
        Self(
            config_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        )
    }

    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() || path.starts_with("~") {
            path.to_path_buf()
        } else {
            self.0.join(path)
        }
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

pub fn parse_and_run() -> Result<(), CliError> {
    run(Cli::parse())
}

/// The aligned label of every status line.
pub(crate) fn line(label: &str, value: impl std::fmt::Display) {
    println!("{label:<12}{value}");
}

/// `New` runs before any ring.toml exists, `Target` and `Url` before any RPC client.
pub fn run(cli: Cli) -> Result<(), CliError> {
    if let Command::New(args) = cli.command {
        return Ok(new::run(args)?);
    }
    let mut config = RingConfig::load(&cli.config)?;
    match cli.command {
        Command::Target { target } => {
            RingConfig::set_target(&cli.config, target)?;
            line("target", target.as_str());
            return Ok(());
        }
        Command::Devnet => {
            RingConfig::set_target(&cli.config, Target::Devnet)?;
            config.target = Target::Devnet;
            probe::run_devnet(&config)?;
            return Ok(());
        }
        Command::Localnet(args) => {
            RingConfig::set_target(&cli.config, Target::Localnet)?;
            config.target = Target::Localnet;
            localnet::run(&cli.config, &config, args)?;
            return Ok(());
        }
        _ => {}
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
        Command::Status => status::run(&ctx),
        Command::Deploy(args) => {
            localnet::ensure(&ctx)?;
            deploy::run(&mut ctx, args)?;
        }
        Command::Init(args) => init::run(&mut ctx, args)?,
        Command::Pipeline(args) => pipeline::run(&mut ctx, args)?,
        Command::Transact(args) => transact::run(&mut ctx, args)?,
        Command::Transfer(args) => transact::run_transfer(&mut ctx, args)?,
        Command::RpcCheck => ring_rpc::run_check(&ctx)?,
        Command::Authority(command) => authority::run(&ctx, command)?,
        Command::Reader(command) => reader::run(&mut ctx, command)?,
        Command::List(command) => list::run(&mut ctx, command)?,
        Command::AuditorKey(args) => keys::run(&ctx.project_root, args)?,
        // Handled before the context loads.
        Command::New(_)
        | Command::Target { .. }
        | Command::Url { .. }
        | Command::Devnet
        | Command::Localnet(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum;
    use custom_ring_interface::RULES;
    use zolana_ring_policy::ListId;

    use super::*;

    #[test]
    fn every_referenced_list_has_a_cli_arm() {
        let arms: Vec<ListId> = ListIdArg::value_variants()
            .iter()
            .map(|arm| ListId::from(*arm))
            .collect();
        for list_id in ListId::ALL
            .into_iter()
            .filter(|list_id| transact::references(&RULES, *list_id))
        {
            assert!(arms.contains(&list_id), "{list_id:?} has no cli arm");
        }
    }

    #[test]
    fn explicit_config_roots_local_key_output() {
        let root = std::env::temp_dir().join(format!("ring-config-root-{}", std::process::id()));
        let config_path = root.join(RING_TOML);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        std::fs::write(
            &config_path,
            r#"name = "rooted"
target = "localnet"
program_id = "11111111111111111111111111111111"
authority_keypair = "keys/authority.json"

[localnet]
rpc = "http://127.0.0.1:8899"
indexer = "http://127.0.0.1:8784"
prover = "http://127.0.0.1:3001"
ring_rpc = "http://127.0.0.1:8785"

[devnet]
rpc = "https://api.devnet.solana.com"
indexer = "i"
prover = "p"
ring_rpc = "r"
"#,
        )
        .expect("write config");

        run(Cli {
            config: config_path,
            target: None,
            command: Command::AuditorKey(AuditorKeyArgs {
                key_file: PathBuf::from(AUDITOR_KEY_FILE),
                create: true,
            }),
        })
        .expect("create rooted key");

        assert!(root.join(AUDITOR_KEY_FILE).is_file());
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
