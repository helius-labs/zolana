//! Every command but `new` reads `ring.toml`, the answers `new` recorded.

mod macros;

pub mod assets;
pub mod authority;
pub mod catalogue;
pub mod config;
pub mod controls;
pub mod delegate;
pub mod deploy;
pub mod file;
pub mod fund;
pub mod init;
pub mod keys;
pub mod list;
pub mod localnet;
pub mod member;
pub mod merge;
pub mod new;
pub mod pipeline;
pub mod policy;
pub mod probe;
pub mod release;
pub mod ring_rpc;
pub mod status;
pub mod tool;
pub mod transact;
pub mod ui;
pub mod wizard;
mod workspace;

use std::{
    cell::{OnceCell, RefCell},
    fmt::Display,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context as _, Result};
use clap::{Args, FromArgMatches, Parser, Subcommand};
use custom_ring_interface::{compute_unit_limit, CustomRingError, InstructionTag};
use custom_ring_sdk::{
    CustomRing, RingError, RingOperation, RingSubmission, SettledSubmission,
    MERGE_DEFAULT_INPUT_COUNT,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use zolana_client::{
    AsyncZolanaClient, Blocking, BlockingIndexer, BlockingInsideRuntime, BlockingRpc, ClientError,
    ComputeBudgetConfig, IndexerPollConfig, Rpc, SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::error::ShieldedPoolError;
use zolana_keypair::ShieldedAddress;
use zolana_ring_client::ReaderKey;

pub use crate::{
    config::{CoSignClass, Mint, RingConfig, Service, Target, ThresholdSpec, RING_TOML},
    list::MemberArg,
    policy::ListName,
    ring_rpc::{RingRpcClient, Trust},
    ui::{line, Ask},
};

/// The blocking client the SDK's `async` operations run on.
pub type Zolana = ZolanaClient<SolanaRpc, ZolanaIndexer>;
pub type Chain = AsyncZolanaClient<Blocking<SolanaRpc>, Blocking<ZolanaIndexer>>;

pub const PROGRAM_KEYPAIR_FILE: &str = "keys/program-keypair.json";
pub const AUDITOR_KEY_FILE: &str = "keys/auditor.key";
pub const AUDITOR_PUBKEY_FILE: &str = "keys/auditor.key.pub";
pub const SENDER_KEYPAIR_FILE: &str = "keys/sender-keypair.json";
pub const DEFAULT_TRANSACT_AMOUNT: u64 = 100_000_000;
/// What localnet tops an account up to.
const LOCALNET_BALANCE: u64 = 100_000_000_000;
const MAX_COMPUTE_UNITS: u32 = 1_400_000;
const WAIT_TIMEOUT: Duration = Duration::from_secs(120);
const WAIT_POLL: Duration = Duration::from_millis(500);
/// About two and a half minutes, the backoff doubling to four seconds.
const INDEXER_POLL: IndexerPollConfig = IndexerPollConfig {
    num_retries: 40,
    delay_ms: 500,
    max_delay_ms: 4_000,
};

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
    /// Require an auditor disclosure proof for new direct deposits.
    #[command(subcommand)]
    DepositAudit(DepositAuditCommand),
    /// Set or show the permanent delegate, or move a note as the delegate.
    #[command(subcommand)]
    Delegate(DelegateCommand),
    /// Escrow the member's nullifier key in its record of the ring member registry.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Read and write the list bits of member records.
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
    /// Set the list bit of the member's record.
    Add(EntryArgs),
    /// Clear the list bit of the member's record.
    Clear(EntryArgs),
    /// Print whether the member's record carries the list.
    Show(EntryArgs),
    /// Point the list at the ring's own registry or a curator ring's.
    SetSource {
        #[arg(value_enum)]
        list_id: ListName,
        /// Curator ring program id or catalogue name.
        #[arg(long, conflicts_with = "own", required_unless_present = "own")]
        curator: Option<String>,
        /// The ring's own registry.
        #[arg(long)]
        own: bool,
    },
}

#[derive(Debug, Args)]
pub struct EntryArgs {
    #[arg(value_enum)]
    pub list_id: ListName,
    #[command(flatten)]
    pub member: MemberArg,
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
        scope: Vec<CoSignClass>,
        /// `<mint>=<amount>` per mint, `sol` for the native token, withdrawals above it need the co-signer.
        #[arg(long, requires = "signer")]
        threshold: Vec<ThresholdSpec>,
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
    pub mint: Option<Mint>,
    #[arg(long)]
    pub delegate_keypair: PathBuf,
    /// The X25519 auditor read key, separate from the Solana delegate signer.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub auditor_key: PathBuf,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

/// The co-signer of a ring whose scope covers the operation.
#[derive(Debug, Default, Args)]
pub struct CosignerArg {
    /// The co-signer keypair when the ring's co-signer scope covers the operation.
    #[arg(long)]
    pub cosigner_keypair: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Seal the member's nullifier key to the ring auditor and register it, `transfer` does it on first use.
    Register,
}

#[derive(Debug, Subcommand)]
pub enum ReaderCommand {
    /// A base58 Solana key or the 66-hex P-256 key of a passkey.
    Grant { reader: ReaderKey },
    /// Close the reader's record, the rent returns to the authority.
    Revoke { reader: ReaderKey },
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
    /// Record whether first init must require an auditor disclosure proof for deposits.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub deposit_audit: Option<bool>,
    /// A local binary instead of the released ring program.
    #[arg(long)]
    pub program_so: Option<PathBuf>,
    #[arg(long, default_value = PROGRAM_KEYPAIR_FILE)]
    pub program_keypair: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum DepositAuditCommand {
    /// Set the requirement for future deposits and save it in ring.toml.
    Set {
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        required: bool,
    },
    /// Read the current requirement from the ring.
    Show,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Override the deposit proof requirement, ring.toml applies only on first init.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub deposit_audit: Option<bool>,
    /// Hex tagged X25519 auditor key, created by the ring RPC and written here when absent.
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
    #[command(flatten)]
    pub cosigner: CosignerArg,
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
    pub mint: Option<Mint>,
    /// Payer's SPL funding account, its ATA by default.
    #[arg(long)]
    pub token_account: Option<Address>,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Mint to merge, `sol` by default.
    #[arg(long)]
    pub mint: Option<Mint>,
    /// Maximum number of notes to merge, from 2 through 54.
    #[arg(
        long,
        default_value_t = MERGE_DEFAULT_INPUT_COUNT as u64,
        value_parser = clap::value_parser!(u64).range(2..=custom_ring_sdk::MAX_MERGE_INPUTS as u64)
    )]
    pub count: u64,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

/// The arguments a command defaults to, what the pipeline runs each step with.
pub fn defaults<T: Args + FromArgMatches>() -> T {
    let command = T::augment_args(clap::Command::new("defaults"));
    T::from_arg_matches(&command.get_matches_from(["defaults"]))
        .expect("every argument has a default")
}

pub struct Context {
    pub config_path: PathBuf,
    /// The directory of ring.toml, relative key paths resolve against it.
    pub root: PathBuf,
    pub config: RingConfig,
    pub ring: CustomRing,
    pub zolana: Zolana,
    /// The `--catalogue` override, `None` for the bundled file.
    pub catalogue: Option<String>,
    ask: RefCell<Box<dyn Ask>>,
    authority: OnceCell<Keypair>,
}

pub enum Probe<T> {
    Ready(T),
    NotYet,
    Retry(anyhow::Error),
}

impl Context {
    pub fn new(
        config_path: PathBuf,
        mut config: RingConfig,
        ask: Box<dyn Ask>,
        catalogue: Option<String>,
    ) -> Self {
        let root = config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        config.resolve_keypair_paths(|path| resolve(&root, path));
        let urls = config.urls();
        let zolana = ZolanaClient::new(
            SolanaRpc::new(urls.rpc.clone()),
            ZolanaIndexer::new(&urls.indexer),
            urls.prover_client(),
        );
        Self {
            ring: CustomRing::new(config.program_id.0),
            config_path,
            root,
            config,
            zolana,
            catalogue,
            ask: RefCell::new(ask),
            authority: OnceCell::new(),
        }
    }

    /// Relative to the ring directory, an absolute or `~` path as given.
    pub fn path(&self, path: &Path) -> PathBuf {
        resolve(&self.root, path)
    }

    pub fn rpc(&self) -> &SolanaRpc {
        self.zolana.rpc()
    }

    pub fn chain(&self) -> &Chain {
        self.zolana.as_async()
    }

    pub fn block<T, E: From<BlockingInsideRuntime>>(
        &self,
        future: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        self.zolana.block_on(future)
    }

    /// The config authority, read once.
    pub fn authority(&self) -> Result<&Keypair> {
        if let Some(authority) = self.authority.get() {
            return Ok(authority);
        }
        let authority = self.config.config_authority()?;
        Ok(self.authority.get_or_init(|| authority))
    }

    /// For a step that only pays fees and small rent.
    pub fn funded_authority(&self) -> Result<&Keypair> {
        let authority = self.authority()?;
        self.fund(authority.pubkey(), fund::MIN_AUTHORITY_BALANCE)?;
        Ok(authority)
    }

    /// Localnet airdrops what the step spends, devnet waits at the faucet.
    pub fn fund(&self, who: Address, required: u64) -> Result<()> {
        match self.config.target {
            Target::Localnet => {
                if self.rpc().get_balance(who)? < required.max(LOCALNET_BALANCE / 2) {
                    SolanaRpc::new(self.config.urls().rpc.clone())
                        .airdrop(&who, required.max(LOCALNET_BALANCE))?;
                }
                Ok(())
            }
            Target::Devnet => {
                fund::wait_for_balance(self.rpc(), &mut **self.ask.borrow_mut(), who, required)
            }
        }
    }

    /// No airdrop, for a step that must not move the operator's funds itself.
    pub fn require_balance(&self, who: Address, required: u64) -> Result<()> {
        let balance = self.rpc().get_balance(who)?;
        ensure!(
            balance >= required,
            "{who} holds {balance} lamports, {required} are needed"
        );
        Ok(())
    }

    /// Kept between runs, earlier change stays spendable with it.
    pub fn sender(&self) -> Result<Keypair> {
        file::read_or_create_keypair(&self.path(Path::new(SENDER_KEYPAIR_FILE)))
    }

    /// `signers[0]` pays, each ring instruction brings its own compute budget.
    pub fn send(&self, signers: &[&dyn Signer], instructions: &[Instruction]) -> Result<Signature> {
        let payer = signers.first().context("a transaction needs a payer")?;
        let units = instructions
            .iter()
            .map(|instruction| self.compute_units(instruction))
            .fold(0u32, u32::saturating_add)
            .min(MAX_COMPUTE_UNITS);
        self.rpc()
            .create_and_send_transaction(
                instructions,
                payer.pubkey(),
                signers,
                ComputeBudgetConfig::new(units),
            )
            .map_err(|error| match hint(&error) {
                Some(hint) => anyhow::Error::new(error).context(hint),
                None => error.into(),
            })
    }

    /// Resent until the cluster settles it, a stale root is proved again.
    pub fn submit<'a>(
        &self,
        operation: impl Into<RingOperation<'a>>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<Signature> {
        let mut submission = RingSubmission::new(operation);
        match self.block(submission.send_until_settled(self.chain(), payer, signers))? {
            SettledSubmission::Confirmed { signature, .. } => Ok(signature),
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error }.into())
            }
        }
    }

    pub fn wait_for_indexed(&self, signature: Signature) -> Result<()> {
        wait_for_indexed_transaction(&self.zolana, signature)
    }

    pub fn interactive(&self) -> bool {
        self.ask.borrow().interactive()
    }

    pub fn ask_yes(&self, prompt: &str, default: bool) -> Result<bool> {
        self.ask.borrow_mut().confirm(prompt, default)
    }

    /// `--yes` skips the question, without a terminal `needs_yes` is the error.
    pub fn confirm(
        &self,
        yes: bool,
        prompt: &str,
        needs_yes: impl Display,
        declined: impl Display,
    ) -> Result<()> {
        if yes {
            return Ok(());
        }
        ensure!(self.interactive(), "{needs_yes}");
        ensure!(self.ask_yes(prompt, false)?, "{declined}");
        Ok(())
    }

    pub fn ring_rpc(&self) -> RingRpcClient {
        RingRpcClient::new(&self.config.urls().ring_rpc)
    }

    /// `unpinned` applies only when ring.toml pins no service key.
    pub fn trust(&self, unpinned: Trust) -> Result<Trust> {
        match self.config.urls().ring_rpc_pubkey.as_deref() {
            Some(key) => key
                .parse()
                .map(Trust::Pinned)
                .with_context(|| format!("ring_rpc_pubkey {key} is not a base58 key")),
            None => Ok(unpinned),
        }
    }

    fn compute_units(&self, instruction: &Instruction) -> u32 {
        instruction
            .data
            .first()
            .filter(|_| instruction.program_id == self.ring.program_id())
            .and_then(|tag| InstructionTag::try_from(*tag).ok())
            .map_or(
                ComputeBudgetConfig::for_instruction_count(1).cu_limit,
                compute_unit_limit,
            )
    }
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() || path.starts_with("~") {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// What a program refusal means for the operator.
fn hint(error: &ClientError) -> Option<&'static str> {
    let Some(TransactionError::InstructionError(_, InstructionError::Custom(code))) =
        error.transaction_error()
    else {
        return None;
    };
    [
        (CustomRingError::UnauthorizedInitializer as u32, "the program was deployed with an upgrade authority and only that key may create the config"),
        (CustomRingError::UnauthorizedAuthority as u32, "the config is held by another authority, `status` shows it"),
        (CustomRingError::InvalidPolicyRules as u32, "the program refuses the compiled rows, the program log names the refusal"),
        (ShieldedPoolError::UnauthorizedCaller as u32, "ring creation on this cluster is gated by the SPP ring creation authority"),
    ]
    .into_iter()
    .find_map(|(known, hint)| (known == code).then_some(hint))
}

/// An `Err` from `probe` is final, the last `Retry` explains a timeout.
pub fn wait_for<T>(label: impl Display, mut probe: impl FnMut() -> Result<Probe<T>>) -> Result<T> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match probe()? {
            Probe::Ready(value) => return Ok(value),
            Probe::NotYet => {}
            Probe::Retry(error) => last = Some(error),
        }
        thread::sleep(WAIT_POLL);
    }
    let timeout = format!("timed out waiting for {label}");
    Err(match last {
        Some(error) => error.context(timeout),
        None => anyhow::anyhow!(timeout),
    })
}

/// Only an error the indexer calls transient is polled again.
pub fn wait_for_indexed_transaction<R: BlockingRpc, I: BlockingIndexer>(
    zolana: &ZolanaClient<R, I>,
    signature: Signature,
) -> Result<()> {
    zolana
        .wait_for_indexed_transaction(signature, INDEXER_POLL)
        .with_context(|| format!("the indexer did not index {signature}"))
}

pub fn parse_and_run() -> Result<()> {
    run(Cli::parse())
}

/// `New` runs before any ring.toml exists, `Target` and `Url` before any RPC client.
pub fn run(cli: Cli) -> Result<()> {
    let silent = matches!(&cli.command, Command::New(args) if args.silent);
    let mut ask = ui::ask_for(silent);
    if let Command::New(args) = cli.command {
        return new::run(args, ask.as_mut(), cli.catalogue.as_deref());
    }
    let mut config = RingConfig::load(&cli.config)?;
    let recorded = match &cli.command {
        Command::Target { target } => Some(*target),
        Command::Devnet => Some(Target::Devnet),
        Command::Localnet(_) => Some(Target::Localnet),
        _ => None,
    };
    if let Some(target) = recorded {
        RingConfig::set_target(&cli.config, target)?;
        config.target = target;
    } else if let Some(target) = cli.target {
        config.target = target;
    }
    match cli.command {
        Command::Target { target } => line("target", target),
        Command::Devnet => probe::run_devnet(&config)?,
        Command::Localnet(args) => localnet::run(&cli.config, &config, args)?,
        Command::Url { service } => println!("{}", config.urls().service(service)),
        command => {
            let mut ctx = Context::new(cli.config, config, ask, cli.catalogue);
            dispatch(&mut ctx, command)?;
        }
    }
    Ok(())
}

fn dispatch(ctx: &mut Context, command: Command) -> Result<()> {
    match command {
        Command::Status => status::run(ctx),
        Command::Deploy(args) => {
            localnet::ensure(ctx)?;
            deploy::run(ctx, args)
        }
        Command::Init(args) => init::run(ctx, args),
        Command::Pipeline(args) => pipeline::run(ctx, args),
        Command::Transact(args) => transact::run(ctx, args),
        Command::Transfer(args) => transact::run_transfer(ctx, args),
        Command::Merge(args) => merge::run(ctx, args),
        Command::RpcCheck => ring_rpc::run_check(ctx),
        Command::Authority(command) => authority::run(ctx, command),
        Command::Reader(command) => controls::reader(ctx, command),
        Command::Cosigner(command) => controls::cosigner(ctx, command),
        Command::DepositAudit(command) => controls::deposit_audit(ctx, command),
        Command::Delegate(command) => controls::delegate(ctx, command),
        Command::Key(command) => member::key(ctx, command),
        Command::List(command) => list::run(ctx, command),
        Command::Policy(command) => policy::run(ctx, command),
        Command::AuditorKey(args) => keys::run(&ctx.path(&args.key_file), args.create),
        Command::New(_)
        | Command::Target { .. }
        | Command::Url { .. }
        | Command::Devnet
        | Command::Localnet(_) => bail!("handled before the context loads"),
    }
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
    fn deposit_audit_is_opt_in_and_can_be_disabled_explicitly() {
        let parse = |args| Cli::try_parse_from(args).unwrap().command;
        assert!(matches!(
            parse(vec!["zolana-ring", "deploy"]),
            Command::Deploy(DeployArgs {
                deposit_audit: None,
                ..
            })
        ));
        assert!(matches!(
            parse(vec!["zolana-ring", "deploy", "--deposit-audit"]),
            Command::Deploy(DeployArgs {
                deposit_audit: Some(true),
                ..
            })
        ));
        assert!(matches!(
            parse(vec!["zolana-ring", "init", "--deposit-audit=false"]),
            Command::Init(InitArgs {
                deposit_audit: Some(false),
                ..
            })
        ));
        assert!(matches!(
            parse(vec![
                "zolana-ring",
                "deposit-audit",
                "set",
                "--required",
                "false"
            ]),
            Command::DepositAudit(DepositAuditCommand::Set { required: false })
        ));
        assert!(Cli::try_parse_from(["zolana-ring", "deposit-audit", "set"]).is_err());
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
    fn merge_takes_an_optional_mint_in_any_spelling_and_a_bounded_count() {
        let mint = Address::new_from_array([7; 32]);
        let parse = |args: &[&str]| {
            let argv = ["zolana-ring", "merge"].iter().chain(args).copied();
            match Cli::try_parse_from(argv).map(|cli| cli.command) {
                Ok(Command::Merge(args)) => Ok(args),
                Ok(_) => panic!("merge"),
                Err(error) => Err(error),
            }
        };
        let args = parse(&["--mint", &mint.to_string(), "--count", "4"]).expect("parses");
        assert_eq!((args.mint, args.count), (Some(Mint(mint)), 4));
        for sol in ["sol", "SOL"] {
            let args = parse(&["--mint", sol]).expect("sol");
            assert_eq!(args.mint, Some(Mint(zolana_transaction::SOL_MINT)));
        }
        assert_eq!(parse(&[]).expect("defaults").count, 24);
        assert!(parse(&["--count", "54"]).is_ok());
        assert!(parse(&["--count", "55"]).is_err());
        assert!(parse(&["--count", "1"]).is_err());
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
        assert_eq!(args.mint, Some(Mint(mint)));
        assert_eq!(args.token_account, Some(token));
        assert_eq!(args.amount, 123);
    }

    #[test]
    fn the_pipeline_runs_init_with_the_command_defaults() {
        let pipeline: InitArgs = defaults();
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
            resolve(Path::new("ring"), &pipeline.auditor_pubkey_file),
            Path::new("ring/keys/auditor.key.pub")
        );
        let transact: TransactArgs = defaults();
        assert_eq!(transact.amount, DEFAULT_TRANSACT_AMOUNT);
        assert!(transact.cosigner.cosigner_keypair.is_none());
    }

    fn transaction_error(error: TransactionError) -> ClientError {
        ClientError::SolanaRpcTransaction {
            operation: "test",
            source: solana_rpc_client_api::client_error::Error {
                request: None,
                kind: Box::new(
                    solana_rpc_client_api::client_error::ErrorKind::TransactionError(error),
                ),
            },
        }
    }

    #[test]
    fn only_a_known_custom_instruction_error_yields_a_hint() {
        let custom = |code| {
            transaction_error(TransactionError::InstructionError(
                1,
                InstructionError::Custom(code),
            ))
        };
        assert!(hint(&custom(CustomRingError::UnauthorizedAuthority as u32))
            .is_some_and(|hint| hint.contains("another authority")));
        assert_eq!(hint(&custom(1)), None);
        assert_eq!(
            hint(&transaction_error(TransactionError::AlreadyProcessed)),
            None
        );
        assert_eq!(hint(&ClientError::Rpc(String::new())), None);
    }

    #[test]
    fn the_indexer_wait_retries_only_a_transient_failure() {
        use std::sync::atomic::{AtomicU8, Ordering};

        use zolana_client::{
            GetShieldedTransactionsBySignatureResponse, IndexedShieldedTransaction,
            IndexerRpcConfig, ProverClient, ShieldedTransaction, WitnessReader,
        };

        /// Fails once, transiently when `transient`, then indexes the signature.
        struct Indexer {
            calls: AtomicU8,
            transient: bool,
        }

        impl WitnessReader for Indexer {}

        impl Rpc for Indexer {
            fn should_retry(&self, error: &ClientError) -> bool {
                matches!(error, ClientError::IndexerUnavailable(_))
            }

            fn get_shielded_transactions_by_signature(
                &self,
                _signature: Signature,
                _config: Option<IndexerRpcConfig>,
            ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
                if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(match self.transient {
                        true => ClientError::IndexerUnavailable("restarting".to_owned()),
                        false => ClientError::Rpc("refused".to_owned()),
                    });
                }
                Ok(GetShieldedTransactionsBySignatureResponse {
                    context: zolana_client::Context {
                        block_time: 0,
                        slot: 1,
                    },
                    output_tree_id: None,
                    transactions: vec![IndexedShieldedTransaction {
                        event_index: 0,
                        transaction: ShieldedTransaction {
                            slot: 1,
                            tx_signature: Signature::default(),
                            event_index: None,
                            tx_viewing_pk: None,
                            salt: None,
                            output_slots: Vec::new(),
                            messages: Vec::new(),
                            nullifiers: Vec::new(),
                            proofless: true,
                            ring_config: None,
                            ring_program_id: None,
                        },
                    }],
                })
            }
        }

        struct NoRpc;
        impl Rpc for NoRpc {}

        let client = |transient| {
            ZolanaClient::new(
                NoRpc,
                Indexer {
                    calls: AtomicU8::new(0),
                    transient,
                },
                ProverClient::local(),
            )
        };
        let transient = client(true);
        wait_for_indexed_transaction(&transient, Signature::default()).expect("indexed");
        assert_eq!(transient.indexer().calls.load(Ordering::Relaxed), 2);
        let permanent = client(false);
        assert!(wait_for_indexed_transaction(&permanent, Signature::default()).is_err());
        assert_eq!(permanent.indexer().calls.load(Ordering::Relaxed), 1);
    }
}
