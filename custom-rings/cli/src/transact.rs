use std::time::{Duration, Instant};

use custom_ring_sdk::{
    AccountReadError, AuditedTransfer, AuditedTransferInput, CustomRing, DepositError, RingDeposit,
    RingDepositReceipt, SendV0Error, TransferError, TransferProofEnvironment, V0WithLookupTable,
};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc, SppProofInputUtxo, ZolanaIndexer};
use zolana_interface::DEFAULT_TREE_ADDRESS;
use zolana_keypair::{shielded::ShieldedAddress, KeypairError, ShieldedKeypair};
use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_transaction::{
    instructions::transact::ConfidentialTransfer, AssetRegistry, TransactionError, SOL_MINT,
};

use crate::{
    init::{configured_auditor_pk, InitError},
    line,
    ring_rpc::{RingRpcClient, RingRpcClientError, TransactionLookup},
    Context, ContextError, TransactArgs, TransferArgs,
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
    pub amount: u64,
}

/// One transfer out of a throwaway sender the payer funds and then abandons.
/// Whatever the two deposits hold above `amount` stays with the sender.
struct RingTransfer<'a> {
    ring: CustomRing,
    payer: &'a dyn Signer,
    deposits: [u64; 2],
    recipient: ShieldedAddress,
    amount: u64,
    tree: Address,
    assets: &'a AssetRegistry,
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
    Init(#[from] InitError),
    #[error(transparent)]
    ReaderKey(#[from] ReaderKeyError),
    #[error(transparent)]
    RingRpc(#[from] RingRpcClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Indexer(#[from] WaitError<ClientError>),
    #[error("reader {reader} is not granted, run `grant-reader {reader}` first")]
    ReaderNotGranted { reader: ReaderKey },
    #[error("amount {amount} does not split across the two deposits a ring transfer spends")]
    AmountTooSmall { amount: u64 },
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
/// The sender is a throwaway key, so nothing of the amount stays behind.
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
        deposits: [half, args.amount - half],
        recipient: args.to,
        amount: args.amount,
        tree: Address::from_str_const(DEFAULT_TREE_ADDRESS),
        assets: &AssetRegistry::default(),
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
        let auditor_pk = configured_auditor_pk(&ctx.rpc, ctx.ring)?;
        let ring_rpc = ctx.ring_rpc();
        ring_rpc.check_serves(ctx.ring.program_id(), &auditor_pk)?;
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
        // The demo deposits the amount twice and keeps the change, so the
        // sender's balance shows in the auditor's view next to the payment.
        let sent = RingTransfer {
            ring: self.ring,
            payer: self.payer,
            deposits: [self.amount; 2],
            recipient: recipient.shielded_address()?,
            amount: self.amount,
            tree: Address::from_str_const(DEFAULT_TREE_ADDRESS),
            assets: &AssetRegistry::default(),
        }
        .send(env)?;

        Ok(TransferReceipt {
            sender: sent.sender,
            recipient,
            deposits: sent.deposits,
            transact: sent.transact,
        })
    }
}

impl RingTransfer<'_> {
    fn send(
        self,
        env: TransferProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<SentTransfer, TransactError> {
        let rpc = env.rpc;
        let sender = ShieldedKeypair::new_ed25519()?;

        // Two deposits fill both input slots of IN2_OUT3, the shape the three
        // outputs (two change slots and the recipient) resolve to.
        let mut utxos = Vec::with_capacity(self.deposits.len());
        let mut deposits = Vec::with_capacity(self.deposits.len());
        for amount in self.deposits {
            let RingDepositReceipt { signature, utxo } = RingDeposit {
                ring: self.ring,
                payer: self.payer,
                recipient: &sender,
                tree: self.tree,
                amount,
            }
            .send(env.rpc)?;
            utxos.push(utxo);
            deposits.push(signature);
        }
        // The instruction does not fit a packet with a separate fee payer, so
        // the sender pays its own v0 transaction and the lookup table behind it.
        let fee = solana_system_interface::instruction::transfer(
            &self.payer.pubkey(),
            &sender.pubkey(),
            SENDER_FEE_BUDGET,
        );
        env.rpc
            .create_and_send_transaction(&[fee], self.payer.pubkey(), &[self.payer])?;

        let inputs = utxos
            .into_iter()
            .map(|utxo| SppProofInputUtxo::new(utxo, &sender))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address()?, inputs, sender.pubkey())
                .with_compact_change();
        transfer.send(&self.recipient, SOL_MINT, self.amount)?;
        let prepared = transfer.prepare()?;
        let proven = AuditedTransfer::new(AuditedTransferInput {
            ring: self.ring,
            sender: &sender,
            prepared,
        })
        .with_tree(self.tree)
        .with_assets(self.assets)
        .prove(env)?;
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
