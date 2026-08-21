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
use zolana_keypair::{KeypairError, ShieldedKeypair};
use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_transaction::{
    instructions::transact::ConfidentialTransfer, AssetRegistry, TransactionError, SOL_MINT,
};

use crate::{
    init::{configured_auditor_pk, InitError},
    reader::{outcome_label, ReaderAccess, ReaderError},
    ring_rpc::{RingRpcClientError, TransactionLookup},
    Context, ContextError, TransactArgs,
};

/// Covers the sender's lookup table rent and fees.
const SENDER_FEE_BUDGET: u64 = 20_000_000;
/// Lookup table rent, the deposit and transact fees.
const PAYER_FEE_BUDGET: u64 = 10_000_000;
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[must_use]
pub struct DemoTransfer<'a> {
    ring: CustomRing,
    /// The sender is funded from here and then pays its own v0 transaction.
    payer: &'a dyn Signer,
    amount: u64,
    /// `DEFAULT_TREE_ADDRESS` unless set.
    tree: Option<Address>,
    /// `AssetRegistry::default()` unless set.
    assets: Option<&'a AssetRegistry>,
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
    Reader(#[from] ReaderError),
    #[error(transparent)]
    RingRpc(#[from] RingRpcClientError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Indexer(#[from] WaitError<ClientError>),
    #[error("authority {authority} holds {balance} lamports, the demo needs {needed}")]
    InsufficientFunds {
        authority: Address,
        balance: u64,
        needed: u64,
    },
}

impl From<ClientError> for TransactError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, args: TransactArgs) -> Result<(), TransactError> {
    let authority = ctx.funded_authority()?;
    let ring = ctx.ring;
    let auditor_pk = configured_auditor_pk(&ctx.rpc, ring)?;
    let ring_rpc = ctx.ring_rpc();
    ring_rpc.check_serves(ring.program_id(), &auditor_pk)?;
    let reader_key = ReaderKey::ed25519(authority.pubkey())?;
    let granted = ReaderAccess {
        ring,
        authority: &authority,
        reader: reader_key,
    }
    .grant(&ctx.rpc)?;
    println!("reader      {reader_key} {}", outcome_label(granted));
    let needed = args
        .amount
        .saturating_mul(2)
        .saturating_add(SENDER_FEE_BUDGET)
        .saturating_add(PAYER_FEE_BUDGET);
    let balance = ctx.rpc.get_balance(authority.pubkey())?;
    if balance < needed {
        return Err(TransactError::InsufficientFunds {
            authority: authority.pubkey(),
            balance,
            needed,
        });
    }
    let indexer = ctx.indexer();
    let prover = ctx.prover();
    let receipt =
        DemoTransfer::new(ring, &authority, args.amount).run(TransferProofEnvironment {
            indexer: &indexer,
            rpc: &ctx.rpc,
            prover: &prover,
        })?;
    println!(
        "sender      {}  viewing pk {}",
        receipt.sender.pubkey(),
        hex::encode(receipt.sender.viewing_pubkey().as_bytes())
    );
    println!(
        "recipient   {}  viewing pk {}",
        receipt.recipient.pubkey(),
        hex::encode(receipt.recipient.viewing_pubkey().as_bytes())
    );
    for signature in &receipt.deposits {
        println!("deposit     {signature}");
    }
    println!("transact    {}", receipt.transact);
    for line in program_logs(&ctx.rpc, &receipt.transact)? {
        println!("  log       {line}");
    }
    println!("waiting for the indexer and the ring rpc to open the transaction");
    wait_for_indexed_transaction(&indexer, receipt.transact)?;
    let opened = ring_rpc.wait_for_decrypted(TransactionLookup {
        ring: ring.program_id(),
        reader: &authority,
        signature: receipt.transact,
    })?;
    println!("auditor sees slot {} at {}", opened.slot, receipt.transact);
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

impl<'a> DemoTransfer<'a> {
    pub fn new(ring: CustomRing, payer: &'a dyn Signer, amount: u64) -> Self {
        Self {
            ring,
            payer,
            amount,
            tree: None,
            assets: None,
        }
    }

    #[must_use = "use the updated transfer"]
    pub fn with_tree(mut self, tree: Address) -> Self {
        self.tree = Some(tree);
        self
    }

    #[must_use = "use the updated transfer"]
    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.assets = Some(assets);
        self
    }

    pub fn run(
        self,
        env: TransferProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
    ) -> Result<TransferReceipt, TransactError> {
        let tree = self
            .tree
            .unwrap_or(Address::from_str_const(DEFAULT_TREE_ADDRESS));
        let default_assets;
        let assets = match self.assets {
            Some(assets) => assets,
            None => {
                default_assets = AssetRegistry::default();
                &default_assets
            }
        };
        let rpc = env.rpc;
        let sender = ShieldedKeypair::new_ed25519()?;
        let recipient = ShieldedKeypair::new_ed25519()?;

        // Two deposits give the (2, 2) shape SPP's ring transfer key supports.
        let mut utxos = Vec::with_capacity(2);
        let mut deposits = Vec::with_capacity(2);
        for _ in 0..2 {
            let RingDepositReceipt { signature, utxo } = RingDeposit {
                ring: self.ring,
                payer: self.payer,
                recipient: &sender,
                tree,
                amount: self.amount,
            }
            .send(env.rpc)?;
            utxos.push(utxo);
            deposits.push(signature);
        }
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
            ConfidentialTransfer::new(sender.shielded_address()?, inputs, sender.pubkey());
        transfer.send(&recipient.shielded_address()?, SOL_MINT, self.amount)?;
        let prepared = transfer.prepare()?;
        let proven = AuditedTransfer::new(AuditedTransferInput {
            ring: self.ring,
            sender: &sender,
            prepared,
        })
        .with_tree(tree)
        .with_assets(assets)
        .prove(env)?;
        let transact = V0WithLookupTable {
            payer: &sender,
            signers: &[],
            instruction: proven.instruction()?,
        }
        .send(rpc)?;

        Ok(TransferReceipt {
            sender,
            recipient,
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
