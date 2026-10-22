//! Every command but `new` reads `ring.toml`, the answers `new` recorded.

mod macros;

pub mod address;
pub mod assets;
pub mod audit;
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
mod records;
pub mod release;
pub mod ring_rpc;
pub mod status;
pub mod tool;
pub mod transact;
pub mod ui;
pub mod wallet;
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
    CustomRing, CustomRingConfig, PendingFirstContact, RingError, RingMode, RingOperation,
    RingSubmission, SettledSubmission, MERGE_DEFAULT_INPUT_COUNT,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use zolana_client::{
    prover::tee::TeePolicy, AsyncZolanaClient, Blocking, BlockingIndexer, BlockingInsideRuntime,
    BlockingRpc, ClientError, ComputeBudgetConfig, IndexerPollConfig, Rpc, SolanaRpc, ZolanaClient,
    ZolanaIndexer,
};
use zolana_interface::error::ShieldedPoolError;
use zolana_keypair::ShieldedAddress;
use zolana_ring_client::ReaderKey;

pub use crate::{
    address::PairingRowArg,
    config::{CoSignClass, Mint, ModeName, RingConfig, Service, Target, ThresholdSpec, RING_TOML},
    list::{MemberArgs, MemberList},
    policy::ListName,
    records::Queued,
    ring_rpc::{RingRpcClient, Trust},
    transact::{Funding, Recipient},
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
    /// Require the prover to attest to the TEE policy in FILE, bare or as a {"deployment": ...}
    /// pin file, in place of the release pin.
    #[arg(
        long,
        value_name = "FILE",
        global = true,
        env = "RING_PROVER_TEE_POLICY"
    )]
    pub prover_tee_policy: Option<PathBuf>,
    /// Pays the member operations of an anonymous ring, never the hidden owner.
    #[arg(
        long,
        value_name = "FILE",
        global = true,
        env = "RING_FEE_PAYER_KEYPAIR"
    )]
    pub fee_payer_keypair: Option<PathBuf>,
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
    /// Pay recipients inside the ring from fresh deposits or from the sender's notes.
    Transfer(TransferArgs),
    /// Deposit into the sender's ring balance, every deposit carries its audit proof.
    Deposit(DepositArgs),
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
    /// Set or show the lamports a member's record write pays the config authority.
    #[command(subcommand)]
    InsertFee(InsertFeeCommand),
    /// Set or show the permanent delegate, or move a note as the delegate.
    #[command(subcommand)]
    Delegate(DelegateCommand),
    /// Escrow the member's nullifier key in its record of the ring member registry.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Read and write the list bits of member records and apply the record queue.
    #[command(subcommand)]
    List(ListCommand),
    /// Read, check and replace the pinned rule table.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Print the local auditor key's public key, or create the key file.
    AuditorKey(AuditorKeyArgs),
    /// Open the ring's transactions with the auditor key, read from the indexer.
    Audit(AuditArgs),
    /// Issue a `zolana:` address of the member, what an anonymous ring pays.
    Address(AddressArgs),
}

#[derive(Debug, Subcommand)]
pub enum ListCommand {
    /// Set the list bit of each member's record, the pending writes apply in the same proof.
    Add(EntryArgs),
    /// Clear the list bit of each member's record.
    Clear(EntryArgs),
    /// Print whether each member's record carries the list.
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
    /// Apply the queued member writes once the queue is full or aged, anyone may.
    Apply,
    /// Set a list the sender writes on its own record, it applies with the queue.
    Join {
        #[arg(value_enum)]
        list: MemberList,
    },
    /// Clear a list the sender writes on its own record.
    Leave {
        #[arg(value_enum)]
        list: MemberList,
    },
}

#[derive(Debug, Args)]
pub struct EntryArgs {
    #[arg(value_enum)]
    pub list_id: ListName,
    #[command(flatten)]
    pub members: MemberArgs,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// The pinned rows, hash, generation and sources.
    Show,
    /// Compare ring.toml with the chain, exits non-zero on a difference.
    Check,
    /// Replace the pinned table with ring.toml under the config authority.
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
pub enum InsertFeeCommand {
    /// Zero lets members write their records free.
    Set {
        lamports: u64,
    },
    Show,
}

#[derive(Debug, Subcommand)]
pub enum DelegateCommand {
    /// Set the delegate once, signed by the delegate and by the upgrade authority holding the ring
    /// auditor key.
    Set {
        /// The delegate's keypair, it signs the set and every later move.
        #[arg(long)]
        delegate_keypair: PathBuf,
    },
    Show,
    /// Move a source member's ring balance to shielded addresses over the delegate rail.
    Move(Box<DelegateMoveArgs>),
}

#[derive(Debug, Args)]
pub struct DelegateMoveArgs {
    /// Each recipient's base58 shielded address, every one receives the amount.
    #[arg(required = true, num_args = 1..)]
    pub to: Vec<ShieldedAddress>,
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
pub struct AuditArgs {
    /// The X25519 auditor read key the ring config pins.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub auditor_key: PathBuf,
    /// Continue from the hex cursor an earlier run printed.
    #[arg(long)]
    pub cursor: Option<String>,
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
pub struct AddressArgs {
    /// An issued index to print again or one inside the discovery gap, the next index by default.
    #[arg(long)]
    pub index: Option<u32>,
    /// Issue `--index` past the discovery gap, every later scan reads each index below it.
    #[arg(long, requires = "index")]
    pub beyond_gap: bool,
    /// The member's Solana keypair, `keys/sender-keypair.json` by default.
    #[arg(long)]
    pub keypair: Option<PathBuf>,
    /// A first contact of the mint at or above the amount opens a pair stream, `any:<min>`
    /// for every mint, at most four, a new address takes `any:0`.
    #[arg(long, value_name = "MINT:MIN")]
    pub pairing: Vec<PairingRowArg>,
    /// Every payment to the address takes the inbox stream.
    #[arg(long, conflicts_with = "pairing")]
    pub no_pairing: bool,
    /// Requested amount in base units, unauthenticated like the mint and label.
    #[arg(long)]
    pub amount: Option<u64>,
    #[arg(long)]
    pub mint: Option<Mint>,
    #[arg(long)]
    pub label: Option<String>,
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
    /// Each recipient, a base58 shielded address on a confidential ring, a `zolana:` request
    /// on an anonymous one, or a shielded address with `--default-ring`.
    #[arg(required = true, num_args = 1..)]
    pub to: Vec<Recipient>,
    /// Base units each recipient receives, a request's own amount or the default when absent.
    #[arg(long)]
    pub amount: Option<u64>,
    /// Registered mint, a request's own mint or `sol` when absent.
    #[arg(long)]
    pub mint: Option<Mint>,
    /// Payer's SPL funding account, its ATA by default.
    #[arg(long)]
    pub token_account: Option<Address>,
    /// `deposit` funds the payments with two fresh deposits, `held` spends the sender's notes
    /// of the ring, and of the default ring unless the ring is anonymous.
    #[arg(long, value_enum, default_value_t = Funding::Deposit)]
    pub funding: Funding,
    /// The fewest output slots, dummies fill what the payments and the change leave.
    #[arg(long)]
    pub outputs: Option<usize>,
    /// An anonymous ring pays each shielded recipient a default-ring note, the value leaves the ring.
    #[arg(long)]
    pub default_ring: bool,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

#[derive(Debug, Args)]
pub struct DepositArgs {
    /// Base units the authority deposits into the sender's ring balance.
    #[arg(
        long,
        default_value_t = DEFAULT_TRANSACT_AMOUNT,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
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
    /// Maximum number of notes to merge, from 2 through 50.
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
    fee_payer_keypair: Option<PathBuf>,
    fee_payer: OnceCell<Keypair>,
}

#[must_use]
pub struct ContextSetup {
    pub config_path: PathBuf,
    pub config: RingConfig,
    pub ask: Box<dyn Ask>,
    pub catalogue: Option<String>,
    pub prover_tee_policy: Option<TeePolicy>,
    pub fee_payer_keypair: Option<PathBuf>,
}

pub enum Probe<T> {
    Ready(T),
    NotYet,
    Retry(anyhow::Error),
}

pub struct Landed {
    pub signature: Signature,
    pub first_contacts: Vec<PendingFirstContact>,
}

#[must_use]
pub struct Landing<'a> {
    pub operation: RingOperation<'a>,
    pub payer: &'a (dyn Signer + Sync),
    pub signers: &'a [&'a (dyn Signer + Sync)],
}

impl ContextSetup {
    pub fn open(self) -> Result<Context> {
        let ContextSetup {
            config_path,
            mut config,
            ask,
            catalogue,
            prover_tee_policy,
            fee_payer_keypair,
        } = self;
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
            urls.prover_client(prover_tee_policy)?,
        );
        Ok(Context {
            ring: CustomRing::new(config.program_id.0),
            config_path,
            root,
            config,
            zolana,
            catalogue,
            ask: RefCell::new(ask),
            authority: OnceCell::new(),
            fee_payer_keypair,
            fee_payer: OnceCell::new(),
        })
    }
}

impl Landing<'_> {
    /// Resent until the cluster settles it, a stale root is proved again.
    pub fn settle(self, zolana: &Zolana) -> Result<Landed> {
        let mut submission = RingSubmission::new(self.operation);
        let settled = zolana.block_on(submission.send_until_settled(
            zolana.as_async(),
            self.payer,
            self.signers,
        ))?;
        match settled {
            SettledSubmission::Confirmed {
                signature,
                first_contacts,
                ..
            } => Ok(Landed {
                signature,
                first_contacts,
            }),
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error }.into())
            }
        }
    }
}

impl Context {
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

    pub fn ring_config(&self) -> Result<CustomRingConfig> {
        self.block(self.ring.config(self.chain()))?
            .context("the ring has no config, run `zolana-ring init` first")
    }

    /// The config authority, read once.
    pub fn authority(&self) -> Result<&Keypair> {
        if let Some(authority) = self.authority.get() {
            return Ok(authority);
        }
        let authority = self.config.config_authority()?;
        Ok(self.authority.get_or_init(|| authority))
    }

    /// An anonymous ring's member operations take `--fee-payer-keypair`, apart from the hidden owner.
    pub(crate) fn member_payer(&self, mode: RingMode, owner: Address) -> Result<&Keypair> {
        if mode != RingMode::Anonymous {
            return self.authority();
        }
        let payer = match self.fee_payer.get() {
            Some(payer) => payer,
            None => {
                let path = self.fee_payer_keypair.as_deref().context(
                    "an anonymous ring pays its member operations from --fee-payer-keypair, a key apart from the hidden owner",
                )?;
                let payer = file::read_keypair(&self.path(path))?;
                self.fee_payer.get_or_init(|| payer)
            }
        };
        ensure!(
            payer.pubkey() != owner,
            "the fee payer {owner} is the hidden owner, paying would publish it"
        );
        Ok(payer)
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

    pub fn submit<'a>(
        &self,
        operation: impl Into<RingOperation<'a>>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<Signature> {
        Ok(self.land(operation, payer, signers)?.signature)
    }

    pub(crate) fn land<'a>(
        &self,
        operation: impl Into<RingOperation<'a>>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<Landed> {
        Landing {
            operation: operation.into(),
            payer,
            signers,
        }
        .settle(&self.zolana)
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
        (CustomRingError::QueueFull as u32, "the record queue holds its member share, `zolana-ring list apply` applies it once it is due"),
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
            let prover_tee_policy = cli
                .prover_tee_policy
                .as_deref()
                .map(config::read_tee_policy)
                .transpose()?;
            let mut ctx = ContextSetup {
                config_path: cli.config,
                config,
                ask,
                catalogue: cli.catalogue,
                prover_tee_policy,
                fee_payer_keypair: cli.fee_payer_keypair,
            }
            .open()?;
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
        Command::Deposit(args) => transact::run_deposit(ctx, args),
        Command::Merge(args) => merge::run(ctx, args),
        Command::RpcCheck => ring_rpc::run_check(ctx),
        Command::Authority(command) => authority::run(ctx, command),
        Command::Reader(command) => controls::reader(ctx, command),
        Command::Cosigner(command) => controls::cosigner(ctx, command),
        Command::InsertFee(command) => controls::insert_fee(ctx, command),
        Command::Delegate(command) => controls::delegate(ctx, command),
        Command::Key(command) => member::key(ctx, command),
        Command::List(command) => list::run(ctx, command),
        Command::Policy(command) => policy::run(ctx, command),
        Command::AuditorKey(args) => keys::run(&ctx.path(&args.key_file), args.create),
        Command::Audit(args) => audit::run(ctx, args),
        Command::Address(args) => address::run(ctx, args),
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
    fn delegate_set_signs_with_the_delegate_keypair() {
        let parse = |args: &[&str]| {
            let argv = ["zolana-ring", "delegate", "set"]
                .iter()
                .chain(args)
                .copied();
            Cli::try_parse_from(argv).map(|cli| cli.command)
        };
        assert!(matches!(
            parse(&["--delegate-keypair", "keys/delegate.json"]),
            Ok(Command::Delegate(DelegateCommand::Set { delegate_keypair }))
                if delegate_keypair == Path::new("keys/delegate.json")
        ));
        let address = Address::new_from_array([7; 32]).to_string();
        assert!(parse(&["--delegate", &address]).is_err());
        assert!(parse(&[]).is_err());
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
        assert!(parse(&["--count", "50"]).is_ok());
        assert!(parse(&["--count", "51"]).is_err());
        assert!(parse(&["--count", "52"]).is_err());
        assert!(parse(&["--count", "1"]).is_err());
    }

    #[test]
    fn transfer_takes_several_recipients_a_mint_and_its_funding() {
        let mint = Address::new_from_array([7; 32]);
        let token = Address::new_from_array([8; 32]);
        let to = |seed: u8| {
            zolana_keypair::ShieldedKeypair::from_keypair(
                zolana_keypair::SigningKey::from_ed25519_bytes(&[seed; 32]),
            )
            .unwrap()
            .shielded_address()
            .unwrap()
        };
        let parse = |args: &[&str]| {
            let argv = ["zolana-ring", "transfer"].iter().chain(args).copied();
            match Cli::try_parse_from(argv).map(|cli| cli.command) {
                Ok(Command::Transfer(args)) => Ok(args),
                Ok(_) => panic!("transfer"),
                Err(error) => Err(error),
            }
        };
        let (first, second) = (to(1).to_string(), to(2).to_string());
        let args = parse(&[
            &first,
            &second,
            "--amount",
            "123",
            "--mint",
            &mint.to_string(),
            "--token-account",
            &token.to_string(),
            "--outputs",
            "8",
        ])
        .expect("parses");
        assert_eq!(
            args.to,
            [Recipient::Shielded(to(1)), Recipient::Shielded(to(2))]
        );
        assert_eq!(args.mint, Some(Mint(mint)));
        assert_eq!(args.token_account, Some(token));
        assert_eq!((args.amount, args.outputs), (Some(123), Some(8)));
        assert_eq!(args.funding, Funding::Deposit);
        let held = parse(&[&first, "--funding", "held"]).expect("held");
        assert_eq!((held.funding, held.amount), (Funding::Held, None));
        assert!(parse(&[]).is_err(), "a transfer names a recipient");
        assert!(parse(&[&first, "--funding", "faucet"]).is_err());
    }

    #[test]
    fn a_deposit_moves_a_nonzero_amount() {
        let deposit = |amount: &str| {
            Cli::try_parse_from(["zolana-ring", "deposit", "--amount", amount])
                .map(|cli| cli.command)
        };
        assert!(deposit("0").is_err());
        assert!(matches!(
            deposit("1"),
            Ok(Command::Deposit(DepositArgs { amount: 1, .. }))
        ));
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
