//! Every command but `new` reads `ring.toml`, the answers `new` recorded.

pub mod assets;
pub mod authority;
pub mod catalogue;
pub mod config;
pub mod cosigner;
pub mod delegate;
pub mod deploy;
pub mod error;
pub mod file;
pub mod fund;
pub mod init;
pub mod key;
pub mod keys;
pub mod list;
pub mod localnet;
pub mod merge;
pub mod new;
pub mod pipeline;
pub mod policy;
pub mod probe;
pub mod reader;
pub mod release;
pub mod ring_rpc;
pub mod spend;
pub mod status;
pub mod step;
pub mod tool;
pub mod transact;
pub mod ui;
pub mod window;
pub mod wizard;
mod workspace;

use std::path::{Path, PathBuf};

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
    list::MemberArg,
    policy::ListName,
    ring_rpc::{RingRpcClient, Trust},
    ui::{line, Ask},
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
    /// A curator catalogue file or URL instead of the bundled one.
    #[arg(long, global = true, env = "RING_CATALOGUE")]
    pub catalogue: Option<String>,
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
    #[command(alias = "dev")]
    Localnet(LocalnetArgs),
    /// Deploy the released program under the authority, or upgrade it in place.
    Deploy(DeployArgs),
    /// Create the config with the auditor key, pin the policy and register the ring with SPP.
    Init(InitArgs),
    /// Deploy, init, check the ring rpc, grant the authority and transact.
    Pipeline(DeployArgs),
    /// Two ring deposits and one custom-ring transfer, read back from the ring RPC.
    Transact(TransactArgs),
    /// Deposit an amount and send all of it to a shielded address inside the ring.
    Transfer(TransferArgs),
    /// Consolidate existing notes of one asset into one note.
    Merge(MergeArgs),
    /// Confirm the ring RPC in `ring.toml` is up and holds the ring's auditor key.
    RpcCheck,
    /// Transfer or renounce the program's upgrade authority.
    #[command(subcommand)]
    Authority(AuthorityCommand),
    /// Grant or revoke reads on the ring RPC.
    #[command(subcommand)]
    Reader(ReaderCommand),
    /// Set, clear or show the ring's co-signer.
    #[command(subcommand)]
    Cosigner(CoSignerCommand),
    /// Set, clear or show a mint's spend window.
    #[command(subcommand)]
    Window(WindowCommand),
    /// Set or show the permanent delegate, or move a note as the delegate.
    #[command(subcommand)]
    Delegate(DelegateCommand),
    /// Register or show the sender's spend record on a velocity ring.
    #[command(subcommand)]
    Spend(SpendCommand),
    /// Enroll the member's nullifier key in the ring key registry.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Read and mutate the ring's policy entries.
    #[command(subcommand)]
    List(ListCommand),
    /// Read, check and replace the pinned rule table.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Print the local auditor key's public key, or create the key file.
    AuditorKey(AuditorKeyArgs),
}

#[derive(Debug, Subcommand)]
pub enum ListCommand {
    /// Claim or reactivate the member's entry of the list.
    Add {
        #[arg(value_enum)]
        list_id: ListName,
        #[command(flatten)]
        member: MemberArg,
    },
    /// Clear the member's entry, leaving the address claimed.
    Clear {
        #[arg(value_enum)]
        list_id: ListName,
        #[command(flatten)]
        member: MemberArg,
    },
    /// Print the member's live entry.
    Show {
        #[arg(value_enum)]
        list_id: ListName,
        #[command(flatten)]
        member: MemberArg,
    },
    /// Point the list at the ring's own namespace or a curator ring's.
    SetSource {
        #[arg(value_enum)]
        list_id: ListName,
        /// Curator ring program id or catalogue name.
        #[arg(long, conflicts_with = "own", required_unless_present = "own")]
        curator: Option<String>,
        /// The ring's own entries.
        #[arg(long)]
        own: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// The pinned rows, hash, generation, tree and sources.
    Show,
    /// Compare ring.toml with the chain, exits non-zero on a difference.
    Check,
    /// Replace the pinned table with ring.toml under the upgrade authority.
    Set {
        /// Confirms the replacement, proofs built against the old table are refused from now on.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum CoSignerCommand {
    /// Create or replace the co-signer, flags absent means the `[cosigner]` table of ring.toml.
    Set {
        /// The Solana key that signs beside the sender.
        #[arg(long)]
        signer: Option<Address>,
        /// Operation classes the co-signer gates.
        #[arg(long, value_delimiter = ',', requires = "signer")]
        scope: Vec<cosigner::CoSignClass>,
        /// `<mint>=<amount>` per mint, `sol` for the native token, withdrawals above it need the co-signer.
        #[arg(long, requires = "signer")]
        threshold: Vec<config::ThresholdSpec>,
    },
    /// Close the co-signer account, the rent returns to the authority.
    Clear,
    Show,
}

#[derive(Debug, Subcommand)]
pub enum DelegateCommand {
    /// Set the delegate once, signed by the upgrade authority holding the ring auditor key.
    Set {
        #[arg(long)]
        delegate: Address,
    },
    Show,
    /// Move a source member's ring balance to a shielded address over the delegate rail.
    Move(Box<DelegateMoveArgs>),
}

#[derive(Debug, Args)]
pub struct DelegateMoveArgs {
    /// The recipient's base58 shielded address.
    pub to: ShieldedAddress,
    /// The source member's base58 shielded address, its ring notes fund the move.
    #[arg(long)]
    pub source: ShieldedAddress,
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
    /// The mint moved, `sol` by default.
    #[arg(long)]
    pub mint: Option<config::Mint>,
    #[arg(long)]
    pub delegate_keypair: PathBuf,
    /// The ring auditor's secret, it opens the source member's registered key.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub auditor_key: PathBuf,
    /// The co-signer keypair when the ring's co-signer scope covers transfers.
    #[arg(long)]
    pub cosigner_keypair: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum SpendCommand {
    /// Claim the sender's record with zero counters, once per member.
    Register,
    Show,
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Seal the member's nullifier key to the ring auditor and register it, `transfer` does it on first use.
    Register,
}

#[derive(Debug, Subcommand)]
pub enum WindowCommand {
    /// Create or replace the window, the counters restart.
    Set {
        /// A mint address, `sol` for the native token.
        #[arg(long)]
        mint: config::Mint,
        /// Window length, windows start at multiples of it.
        #[arg(long)]
        slots: u64,
        /// Public deposits per window, zero leaves them uncapped.
        #[arg(long, default_value_t = 0)]
        deposit_cap: u64,
        /// Public withdrawals per window, zero leaves them uncapped.
        #[arg(long, default_value_t = 0)]
        withdrawal_cap: u64,
    },
    /// Close the window account, the rent returns to the authority.
    Clear {
        #[arg(long)]
        mint: config::Mint,
    },
    Show {
        #[arg(long)]
        mint: config::Mint,
    },
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
    /// Ring name in kebab-case, also the directory name, asked when absent.
    pub name: Option<String>,
    /// Parent directory the ring is created in.
    #[arg(long, default_value = ".")]
    pub dest: PathBuf,
    /// Answer every question with its default.
    #[arg(long)]
    pub silent: bool,
    /// Recorded in ring.toml, `~` stays literal for other machines.
    #[arg(long, default_value = new::DEFAULT_AUTHORITY_KEYPAIR)]
    pub authority_keypair: String,
    /// A `ring.toml` or any toml file with a `[policy]` table, replaces the policy questions.
    #[arg(long)]
    pub policy_from: Option<PathBuf>,
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
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives, deposited twice by the authority.
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
    /// The co-signer keypair when the ring's co-signer scope covers the demo.
    #[arg(long)]
    pub cosigner_keypair: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct TransferArgs {
    /// The recipient's base58 shielded address, `signing_pk || nullifier_pk || viewing_pk`.
    pub to: ShieldedAddress,
    /// Recipient amount in base units, funded by the authority.
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
    /// Registered mint, `sol` by default.
    #[arg(long)]
    pub mint: Option<config::Mint>,
    /// Payer's SPL funding account, its ATA by default.
    #[arg(long)]
    pub token_account: Option<Address>,
    /// The co-signer keypair when the ring's co-signer scope covers the transfer.
    #[arg(long)]
    pub cosigner_keypair: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Mint to merge; SOL when omitted.
    #[arg(long)]
    pub mint: Option<Address>,
    /// Maximum number of notes to merge, from 2 through 8.
    #[arg(long, default_value_t = 8, value_parser = parse_merge_count)]
    pub count: usize,
    /// The co-signer keypair when the ring's co-signer scope covers transfers.
    #[arg(long)]
    pub cosigner_keypair: Option<PathBuf>,
}

fn parse_merge_count(value: &str) -> Result<usize, String> {
    let count = value
        .parse::<usize>()
        .map_err(|_| "count must be an integer from 2 through 8".to_owned())?;
    (2..=8)
        .contains(&count)
        .then_some(count)
        .ok_or_else(|| "count must be from 2 through 8".to_owned())
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
        }
    }
}

impl Default for TransactArgs {
    fn default() -> Self {
        Self {
            cosigner_keypair: None,
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
    pub ask: Box<dyn Ask>,
    /// The `--catalogue` override, `None` for the bundled file.
    pub catalogue: Option<String>,
}

pub struct Session {
    pub config_path: PathBuf,
    pub config: RingConfig,
    pub ask: Box<dyn Ask>,
    pub catalogue: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectRoot(PathBuf);

#[derive(Debug, Error)]
pub enum ContextError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Fund(#[from] FundError),
    #[error("the authority holds {balance} lamports, {required} are needed")]
    AuthorityUnderfunded { required: u64, balance: u64 },
    #[error(transparent)]
    Client(Box<ClientError>),
}

impl Session {
    pub fn load(self) -> Context {
        let Self {
            config_path,
            mut config,
            ask,
            catalogue,
        } = self;
        let project_root = ProjectRoot::for_config(&config_path);
        config.resolve_keypair_paths(&project_root);
        let ring = CustomRing::new(config.program_id);
        let rpc = SolanaRpc::new(config.urls().rpc.clone());
        Context {
            config_path,
            project_root,
            config,
            ring,
            rpc,
            ask,
            catalogue,
        }
    }
}

impl Context {
    /// For a step that only pays fees and small rent.
    pub fn funded_authority(&mut self) -> Result<Keypair, ContextError> {
        self.authority_funded_for(fund::MIN_AUTHORITY_BALANCE)
    }

    pub fn authority_funded_for(&mut self, required: u64) -> Result<Keypair, ContextError> {
        let authority = self.config.config_authority()?;
        self.fund_authority(&authority, required)?;
        Ok(authority)
    }

    pub fn authority_with_balance(&self, required: u64) -> Result<Keypair, ContextError> {
        let authority = self.config.config_authority()?;
        let balance = self.rpc.get_balance(authority.pubkey())?;
        if balance < required {
            return Err(ContextError::AuthorityUnderfunded { required, balance });
        }
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
            Target::Devnet => {
                fund::wait_for_balance(&self.rpc, self.ask.as_mut(), authority.pubkey(), required)?
            }
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

/// `New` runs before any ring.toml exists, `Target` and `Url` before any RPC client.
pub fn run(cli: Cli) -> Result<(), CliError> {
    let silent = matches!(&cli.command, Command::New(args) if args.silent);
    let mut ask = ui::ask_for(silent);
    if let Command::New(args) = cli.command {
        return Ok(new::run(args, ask.as_mut(), cli.catalogue.as_deref())?);
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
    let mut ctx = Session {
        config_path: cli.config,
        config,
        ask,
        catalogue: cli.catalogue,
    }
    .load();
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
        Command::Merge(args) => merge::run(&mut ctx, args)?,
        Command::RpcCheck => ring_rpc::run_check(&ctx)?,
        Command::Authority(command) => authority::run(&mut ctx, command)?,
        Command::Reader(command) => reader::run(&mut ctx, command)?,
        Command::Cosigner(command) => cosigner::run(&mut ctx, command)?,
        Command::Window(command) => window::run(&mut ctx, command)?,
        Command::Delegate(command) => delegate::run(&mut ctx, command)?,
        Command::Spend(command) => spend::run(&mut ctx, command)?,
        Command::Key(command) => key::run(&mut ctx, command)?,
        Command::List(command) => list::run(&mut ctx, command)?,
        Command::Policy(command) => policy::run(&mut ctx, command)?,
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
    use clap::{CommandFactory, Parser, ValueEnum};
    use zolana_ring_policy::{ListId, Writer};

    use super::*;

    #[test]
    fn the_list_arg_names_every_authority_written_list() {
        let arms: Vec<ListId> = ListName::value_variants()
            .iter()
            .map(|arm| arm.id())
            .collect();
        let authority_written: Vec<ListId> = ListId::ALL
            .into_iter()
            .filter(|list_id| matches!(list_id.writer(), Writer::Authority))
            .collect();
        assert_eq!(arms, authority_written);
        for name in ListName::value_variants() {
            assert_eq!(
                ListName::from_str(name.as_str(), false).expect("parses"),
                *name
            );
        }
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn dev_uses_the_localnet_command() {
        assert!(matches!(
            Cli::try_parse_from(["zolana-ring", "dev", "--no-start"])
                .unwrap()
                .command,
            Command::Localnet(LocalnetArgs { no_start: true })
        ));
    }

    #[test]
    fn merge_takes_an_optional_mint_and_a_bounded_count() {
        let mint = Address::new_from_array([7; 32]);
        let Command::Merge(args) = Cli::try_parse_from([
            "zolana-ring",
            "merge",
            "--mint",
            &mint.to_string(),
            "--count",
            "4",
        ])
        .expect("merge parses")
        .command
        else {
            panic!("merge");
        };
        assert_eq!(args.mint, Some(mint));
        assert_eq!(args.count, 4);
        assert!(Cli::try_parse_from(["zolana-ring", "merge", "--count", "9"]).is_err());
    }

    #[test]
    fn transfer_accepts_registered_mint_and_funding_account() {
        let mint = Address::new_from_array([7; 32]);
        let token = Address::new_from_array([8; 32]);
        let to = zolana_keypair::ShieldedKeypair::new_ed25519()
            .unwrap()
            .shielded_address()
            .unwrap();
        let Command::Transfer(args) = Cli::try_parse_from([
            "zolana-ring",
            "transfer",
            &to.to_string(),
            "--amount",
            "123",
            "--mint",
            &mint.to_string(),
            "--token-account",
            &token.to_string(),
        ])
        .unwrap()
        .command
        else {
            panic!("transfer");
        };
        assert_eq!(args.mint, Some(config::Mint(mint)));
        assert_eq!(args.token_account, Some(token));
        assert_eq!(args.amount, 123);
    }

    #[test]
    fn the_pipeline_init_arguments_are_the_command_defaults() {
        let pipeline = InitArgs::default();
        let Command::Init(command) = Cli::try_parse_from(["zolana-ring", "init"])
            .expect("parses")
            .command
        else {
            panic!("init");
        };
        assert_eq!(command.auditor_pubkey_file, pipeline.auditor_pubkey_file);
        assert_eq!(command.trust_ring_rpc, pipeline.trust_ring_rpc);
        assert_eq!(command.local_auditor, pipeline.local_auditor);
        assert_eq!(
            ProjectRoot::for_config(Path::new("ring/ring.toml"))
                .resolve(&pipeline.auditor_pubkey_file),
            Path::new("ring/keys/auditor.key.pub")
        );
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
            catalogue: None,
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
