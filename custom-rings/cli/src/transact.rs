use std::{
    path::Path,
    time::{Duration, Instant},
};

use custom_ring_interface::RULES;
use custom_ring_sdk::{
    AccountReadError, CustomRing, CustomRingTransfer, CustomRingTransferInput, DepositAsset,
    DepositError, EntryProofEnvironment, RingDeposit, RingDepositReceipt, SendV0Error,
    TransferError, TransferProofEnvironment, V0WithLookupTable,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc, SppProofInputUtxo, ZolanaIndexer};
use zolana_interface::DEFAULT_TREE_ADDRESS;
use zolana_keypair::{shielded::ShieldedAddress, KeypairError, ShieldedKeypair};
use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_ring_policy::{EntryState, ListId, Member, MemberError, Rule, RuleTable};
use zolana_transaction::{
    instructions::transact::ConfidentialTransfer, AssetRegistry, TransactionError, Utxo, SOL_MINT,
};

use crate::{
    file::{self, FileError},
    line,
    list::{EntryMutation, ListError},
    ring_rpc::{RingRpcClient, RingRpcClientError, TransactionLookup},
    Context, ContextError, TransactArgs, TransferArgs, SENDER_KEYPAIR_FILE,
};

/// Covers the sender's lookup table rent and fees.
const SENDER_FEE_BUDGET: u64 = 20_000_000;
/// Lookup table rent, the deposit and transact fees.
const PAYER_FEE_BUDGET: u64 = 10_000_000;
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[must_use]
pub struct DemoTransfer<'a> {
    pub ring: CustomRing,
    /// The sender is funded from here and then pays its own v0 transaction.
    pub payer: &'a dyn Signer,
    pub sender: ShieldedKeypair,
    pub amount: u64,
}

/// Whatever the two deposits hold above `amount` stays with the sender.
struct RingTransfer<'a> {
    ring: CustomRing,
    payer: &'a dyn Signer,
    sender: ShieldedKeypair,
    deposits: [u64; 2],
    recipient: ShieldedAddress,
    amount: u64,
    tree: Address,
    assets: &'a AssetRegistry,
    rules: Option<&'a RuleTable>,
}

struct Deposited<'a> {
    transfer: RingTransfer<'a>,
    utxos: Vec<Utxo>,
    deposits: Vec<Signature>,
}

struct SentTransfer {
    sender: ShieldedKeypair,
    deposits: Vec<Signature>,
    transact: Signature,
}

pub struct TransferReceipt {
    pub sender: ShieldedKeypair,
    pub recipient: ShieldedKeypair,
    pub deposits: Vec<Signature>,
    pub transact: Signature,
}

pub enum Probe<T, E> {
    Ready(T),
    NotYet,
    Retry(E),
}

#[derive(Debug, Error)]
pub enum WaitError<E: std::error::Error + 'static> {
    #[error("timed out waiting for {label}")]
    Timeout {
        label: String,
        #[source]
        last: Option<Box<E>>,
    },
    #[error(transparent)]
    Failed(E),
}

#[derive(Debug, Error)]
pub enum TransactError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Deposit(#[from] DepositError),
    #[error(transparent)]
    Transfer(#[from] TransferError),
    #[error(transparent)]
    SendV0(#[from] SendV0Error),
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    ReaderKey(#[from] ReaderKeyError),
    #[error(transparent)]
    RingRpc(#[from] RingRpcClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Indexer(#[from] WaitError<ClientError>),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    List(Box<ListError>),
    #[error("reader {reader} is not granted, run `grant-reader {reader}` first")]
    ReaderNotGranted { reader: ReaderKey },
    #[error("amount {amount} does not split across the two deposits a ring transfer spends")]
    AmountTooSmall { amount: u64 },
}

impl From<ListError> for TransactError {
    fn from(error: ListError) -> Self {
        Self::List(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, args: TransactArgs) -> Result<(), TransactError> {
    // The demo deposits the amount twice, funded before the first deposit.
    let session = Session::open(ctx, args.amount.saturating_mul(2))?;
    let reader_key = ReaderKey::ed25519(session.authority.pubkey())?;
    if ctx
        .ring
        .read_access_record(&ctx.rpc, &reader_key)?
        .is_none()
    {
        return Err(TransactError::ReaderNotGranted { reader: reader_key });
    }
    let receipt = DemoTransfer {
        ring: ctx.ring,
        payer: &session.authority,
        sender: sender_keypair(ctx)?,
        amount: args.amount,
    }
    .run(session.env(ctx))?;
    line(
        "sender",
        format_args!(
            "{}  viewing pk {}",
            receipt.sender.pubkey(),
            hex::encode(receipt.sender.viewing_pubkey().as_bytes())
        ),
    );
    line(
        "recipient",
        format_args!(
            "{}  viewing pk {}",
            receipt.recipient.pubkey(),
            hex::encode(receipt.recipient.viewing_pubkey().as_bytes())
        ),
    );
    print_signatures(ctx, &receipt.deposits, receipt.transact)?;
    read_back(
        &session.indexer,
        &session.ring_rpc,
        ctx.ring,
        &session.authority,
        receipt.transact,
    )?;
    Ok(())
}

/// Deposit the amount into the ring and send all of it to a shielded address.
pub fn run_transfer(ctx: &mut Context, args: TransferArgs) -> Result<(), TransactError> {
    if args.amount < 2 {
        return Err(TransactError::AmountTooSmall {
            amount: args.amount,
        });
    }
    let session = Session::open(ctx, args.amount)?;
    // The recipient takes the whole amount, so the two deposits split it.
    let half = args.amount / 2;
    let sent = RingTransfer {
        ring: ctx.ring,
        payer: &session.authority,
        sender: sender_keypair(ctx)?,
        deposits: [half, args.amount - half],
        recipient: args.to,
        amount: args.amount,
        tree: Address::from_str_const(DEFAULT_TREE_ADDRESS),
        assets: &AssetRegistry::default(),
        rules: policy_rules(ctx.ring, &ctx.rpc)?,
    }
    .send(session.env(ctx))?;
    line("to", args.to);
    line("amount", format_args!("{} lamports", args.amount));
    line(
        "sender",
        format_args!(
            "{}  a throwaway key, funded and abandoned",
            sent.sender.pubkey()
        ),
    );
    print_signatures(ctx, &sent.deposits, sent.transact)?;
    // Reading the transfer back is a courtesy, the payment is already on chain.
    let reader_key = ReaderKey::ed25519(session.authority.pubkey())?;
    if ctx
        .ring
        .read_access_record(&ctx.rpc, &reader_key)?
        .is_none()
    {
        println!("auditor view skipped, grant-reader {reader_key} to read the ring");
        return Ok(());
    }
    read_back(
        &session.indexer,
        &session.ring_rpc,
        ctx.ring,
        &session.authority,
        sent.transact,
    )?;
    Ok(())
}

/// Opened only after the ring rpc serves the configured auditor.
struct Session {
    authority: solana_keypair::Keypair,
    ring_rpc: RingRpcClient,
    indexer: ZolanaIndexer,
    prover: zolana_client::ProverClient,
}

impl Session {
    fn open(ctx: &mut Context, deposited: u64) -> Result<Self, TransactError> {
        let needed = deposited
            .saturating_add(SENDER_FEE_BUDGET)
            .saturating_add(PAYER_FEE_BUDGET);
        let authority = ctx.authority_funded_for(needed)?;
        let ring_rpc = ctx.ring_rpc();
        ring_rpc.check_serves(ctx.ring.program_id())?;
        Ok(Self {
            authority,
            ring_rpc,
            indexer: ctx.indexer(),
            prover: ctx.prover(),
        })
    }

    fn env<'a>(
        &'a self,
        ctx: &'a Context,
    ) -> TransferProofEnvironment<'a, ZolanaIndexer, SolanaRpc> {
        TransferProofEnvironment {
            indexer: &self.indexer,
            rpc: &ctx.rpc,
            prover: &self.prover,
        }
    }
}

fn print_signatures(
    ctx: &Context,
    deposits: &[Signature],
    transact: Signature,
) -> Result<(), TransactError> {
    for signature in deposits {
        line("deposit", signature);
    }
    line("transact", transact);
    for line in program_logs(&ctx.rpc, &transact)? {
        println!("  log       {line}");
    }
    Ok(())
}

/// What the auditor opens for a granted reader, once the indexer has the slot.
fn read_back(
    indexer: &ZolanaIndexer,
    ring_rpc: &RingRpcClient,
    ring: CustomRing,
    reader: &solana_keypair::Keypair,
    signature: Signature,
) -> Result<(), TransactError> {
    println!("waiting for the indexer and the ring rpc to open the transaction");
    wait_for_indexed_transaction(indexer, signature)?;
    let opened = ring_rpc.wait_for_decrypted(TransactionLookup {
        ring: ring.program_id(),
        reader,
        signature,
    })?;
    println!("auditor sees slot {} at {signature}", opened.slot);
    println!("  nullifiers {}", opened.nullifiers.len());
    for output in &opened.outputs {
        println!(
            "  slot {}  to {}  asset {}  amount {}",
            output.slot_index,
            hex::encode(&output.recipient_viewing_pk.0),
            output.asset.0,
            output.amount
        );
    }
    if !opened.undecryptable_slots.is_empty() {
        println!("  undecryptable slots {:?}", opened.undecryptable_slots);
    }
    Ok(())
}

impl DemoTransfer<'_> {
    pub fn run(
        self,
        env: TransferProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<TransferReceipt, TransactError> {
        let recipient = ShieldedKeypair::new_ed25519()?;
        let rules = policy_rules(self.ring, env.rpc)?;
        let assets = AssetRegistry::default();
        // The demo deposits the amount twice and keeps the change, so the
        // sender's balance shows in the auditor's view next to the payment.
        let deposited = RingTransfer {
            ring: self.ring,
            payer: self.payer,
            sender: self.sender,
            deposits: [self.amount; 2],
            recipient: recipient.shielded_address()?,
            amount: self.amount,
            tree: Address::from_str_const(DEFAULT_TREE_ADDRESS),
            assets: &assets,
            rules,
        }
        .deposit(env.indexer, env.rpc)?;
        if rules.is_some_and(|rules| references(rules, ListId::Allow)) {
            deposited.transfer.enrol_in_allow(EntryProofEnvironment {
                indexer: env.indexer,
                rpc: env.rpc,
                prover: env.prover,
            })?;
        }
        let sent = deposited.prove_and_send(env)?;

        Ok(TransferReceipt {
            sender: sent.sender,
            recipient,
            deposits: sent.deposits,
            transact: sent.transact,
        })
    }
}

impl<'a> RingTransfer<'a> {
    fn send(
        self,
        env: TransferProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<SentTransfer, TransactError> {
        self.deposit(env.indexer, env.rpc)?.prove_and_send(env)
    }

    /// Two deposits fill both input slots of IN2_OUT2, the compact change and
    /// the recipient fill the outputs.
    fn deposit(
        self,
        indexer: &ZolanaIndexer,
        rpc: &SolanaRpc,
    ) -> Result<Deposited<'a>, TransactError> {
        let mut utxos = Vec::with_capacity(self.deposits.len());
        let mut deposits = Vec::with_capacity(self.deposits.len());
        for amount in self.deposits {
            let RingDepositReceipt { signature, utxo } = RingDeposit {
                ring: self.ring,
                payer: self.payer,
                recipient: &self.sender,
                tree: self.tree,
                asset: DepositAsset::Sol,
                amount,
            }
            .send(rpc)?;
            utxos.push(utxo);
            deposits.push(signature);
        }
        // Photon learns a tree from its first indexed transaction.
        if let Some(last) = deposits.last() {
            wait_for_indexed_transaction(indexer, *last)?;
        }
        Ok(Deposited {
            transfer: self,
            utxos,
            deposits,
        })
    }

    /// The table refuses both parties until they are `Active` in `Allow`.
    fn enrol_in_allow(
        &self,
        env: EntryProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<(), TransactError> {
        let curator = self
            .ring
            .read_policy_config(env.rpc)?
            .and_then(|config| config.source_for(ListId::Allow))
            .filter(|namespace| *namespace != self.ring.namespace_pda());
        if let Some(namespace) = curator {
            line("allow", format_args!("curated by {namespace}"));
            return Ok(());
        }
        let parties = [
            (
                "sender",
                self.sender.signing_pubkey().confidential_view_tag()?,
            ),
            ("recipient", self.recipient.confidential_view_tag()?),
        ];
        for (party, tag) in parties {
            let outcome = EntryMutation {
                ring: self.ring,
                authority: self.payer,
                list_id: ListId::Allow,
                member: Member::owner_tag(&tag)?,
                state: EntryState::Active,
            }
            .apply(EntryProofEnvironment {
                indexer: env.indexer,
                rpc: env.rpc,
                prover: env.prover,
            })?;
            line("allow", format_args!("{party} {}", outcome.change.label()));
        }
        Ok(())
    }
}

impl Deposited<'_> {
    fn prove_and_send(
        self,
        env: TransferProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<SentTransfer, TransactError> {
        let rpc = env.rpc;
        let Self {
            transfer: this,
            utxos,
            deposits,
        } = self;
        let sender = this.sender;
        // The instruction does not fit a packet with a separate fee payer, so
        // the sender pays its own v0 transaction and the lookup table behind it.
        let fee = solana_system_interface::instruction::transfer(
            &this.payer.pubkey(),
            &sender.pubkey(),
            SENDER_FEE_BUDGET,
        );
        env.rpc
            .create_and_send_transaction(&[fee], this.payer.pubkey(), &[this.payer])?;

        let inputs = utxos
            .into_iter()
            .map(|utxo| SppProofInputUtxo::new(utxo, &sender))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address()?, inputs, sender.pubkey())
                .with_compact_change()
                .with_ring_program_id(this.ring.program_id());
        transfer.send(&this.recipient, SOL_MINT, this.amount)?;
        let prepared = transfer.prepare()?;
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: this.ring,
            sender: &sender,
            prepared,
        })
        .with_tree(this.tree)
        .with_assets(this.assets);
        if let Some(rules) = this.rules {
            transfer = transfer.with_rules(rules);
        }
        let proven = transfer.prove(env)?;
        let transact = V0WithLookupTable {
            payer: &sender,
            signers: &[],
            instruction: proven.instruction()?,
        }
        .send(rpc)?;

        Ok(SentTransfer {
            sender,
            deposits,
            transact,
        })
    }
}

fn policy_rules(
    ring: CustomRing,
    rpc: &SolanaRpc,
) -> Result<Option<&'static RuleTable>, TransactError> {
    let has_policy = ring
        .read_config(rpc)?
        .is_some_and(|config| config.has_policy);
    Ok(has_policy.then_some(&RULES))
}

pub(crate) fn references(rules: &RuleTable, list_id: ListId) -> bool {
    rules
        .rules()
        .iter()
        .flat_map(Rule::referenced_lists)
        .any(|referenced| referenced == list_id)
}

/// Kept between runs, earlier change stays spendable with it.
fn sender_keypair(ctx: &Context) -> Result<ShieldedKeypair, TransactError> {
    let path = ctx.project_path(Path::new(SENDER_KEYPAIR_FILE));
    let keypair = if path.is_file() {
        file::read_keypair(&path)?
    } else {
        let keypair = Keypair::new();
        file::write_keypair(&keypair, &path)?;
        keypair
    };
    Ok(ShieldedKeypair::from_keypair(&keypair)?)
}

/// An `Err` from `probe` is final, `Retry` is kept for the timeout message.
pub fn wait_for<T, E: std::error::Error + 'static>(
    label: String,
    mut probe: impl FnMut() -> Result<Probe<T, E>, E>,
) -> Result<T, WaitError<E>> {
    let deadline = Instant::now() + INDEXER_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match probe().map_err(WaitError::Failed)? {
            Probe::Ready(value) => return Ok(value),
            Probe::NotYet => {}
            Probe::Retry(error) => last = Some(Box::new(error)),
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(WaitError::Timeout { label, last })
}

pub fn wait_for_indexed_transaction<I: Rpc>(
    indexer: &I,
    signature: Signature,
) -> Result<(), WaitError<ClientError>> {
    wait_for(format!("indexed transaction {signature}"), || {
        Ok(
            match indexer.get_shielded_transactions_by_signature(signature, None) {
                Ok(response) if response.transactions.is_empty() => Probe::NotYet,
                Ok(_) => Probe::Ready(()),
                Err(error) => Probe::Retry(error),
            },
        )
    })
}

fn program_logs(rpc: &SolanaRpc, signature: &Signature) -> Result<Vec<String>, ClientError> {
    let confirmed = rpc.fetch_confirmed_transaction(signature)?;
    let logs: Option<Vec<String>> = confirmed
        .transaction
        .meta
        .map(|meta| meta.log_messages.into())
        .unwrap_or_default();
    Ok(logs
        .unwrap_or_default()
        .into_iter()
        .filter_map(|line| line.strip_prefix("Program log: ").map(str::to_owned))
        .collect())
}
