use std::{
    path::Path,
    time::{Duration, Instant},
};

use custom_ring_sdk::{
    policy_config_table, AccountReadError, CustomRing, CustomRingTransfer, CustomRingTransferInput,
    DepositAsset, DepositError, EntryProofEnvironment, PolicyMatchError, RingDeposit,
    RingDepositReceipt, SendError, TransactSend, TransferError, TransferProofEnvironment,
};
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{
    ClientError, ComputeBudgetConfig, Rpc, SolanaRpc, SppProofInputUtxo, ZolanaIndexer,
};
use zolana_interface::pda;
use zolana_keypair::{shielded::ShieldedAddress, KeypairError, ShieldedKeypair};
use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_ring_policy::{EntryState, ListId, Member, MemberError, RuleTable};
use zolana_transaction::{
    instructions::transact::ConfidentialTransfer, AssetRegistry, TransactionError, Utxo, SOL_MINT,
};

use crate::{
    file::{self, FileError},
    line,
    list::{EntryMutation, ListError},
    ring_rpc::{RingRpcClient, RingRpcClientError, TransactionLookup},
    spend::{Registration, SpendError},
    ui::{self, Icon},
    Context, ContextError, TransactArgs, TransferArgs, SENDER_KEYPAIR_FILE,
};

pub(crate) const SENDER_FEE_BUDGET: u64 = 20_000_000;
pub(crate) const PAYER_FEE_BUDGET: u64 = 10_000_000;
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[must_use]
pub struct DemoTransfer<'a> {
    pub ring: CustomRing,
    pub payer: &'a dyn Signer,
    pub sender: ShieldedKeypair,
    pub amount: u64,
    pub cosigner: Option<&'a dyn Signer>,
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
    asset: DepositAsset,
    cosigner: Option<&'a dyn Signer>,
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
    Send(#[from] SendError),
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
    PolicyMatch(Box<PolicyMatchError>),
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
    #[error(transparent)]
    Spend(Box<SpendError>),
    #[error("the transfer needs the co-signer's approval, pass --cosigner-keypair")]
    ApprovalNeedsCoSigner,
    #[error("the configured co-signer is {expected}, not {found}")]
    WrongCoSigner { expected: Address, found: Address },
    #[error("the policy needs approval but no co-signer is configured")]
    CoSignerNotConfigured,
    #[error(transparent)]
    Asset(Box<crate::assets::AssetError>),
}

impl From<crate::assets::AssetError> for TransactError {
    fn from(error: crate::assets::AssetError) -> Self {
        Self::Asset(Box::new(error))
    }
}

impl From<SpendError> for TransactError {
    fn from(error: SpendError) -> Self {
        Self::Spend(Box::new(error))
    }
}

impl From<ListError> for TransactError {
    fn from(error: ListError) -> Self {
        Self::List(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, args: TransactArgs) -> Result<(), TransactError> {
    let cosigner = cosigner_keypair(ctx, args.cosigner_keypair.as_deref())?;
    CoSignerCheck {
        provided: cosigner.as_ref().map(|keypair| keypair.pubkey()),
        scope: custom_ring_interface::COSIGN_TRANSFERS | custom_ring_interface::COSIGN_DEPOSITS,
        payment: Some(PolicyPayment {
            mint: SOL_MINT,
            amount: args.amount,
        }),
    }
    .check(ctx)?;
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
        cosigner: cosigner.as_ref().map(|keypair| keypair as &dyn Signer),
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
    line("sender tag", owner_tag(&receipt.sender)?);
    line("recipient tag", owner_tag(&receipt.recipient)?);
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
    // 1. Resolve public funding and approval requirements before sending either deposit.
    let mint = args.mint.unwrap_or(SOL_MINT);
    let assets = crate::assets::resolve(&ctx.rpc, mint)?;
    let payer = ctx.config.config_authority().map_err(ContextError::from)?;
    let asset = assets.deposit(
        &ctx.rpc,
        crate::assets::DepositFunding {
            payer: payer.pubkey(),
            token_account: args.token_account,
            amount: args.amount,
        },
    )?;
    let cosigner = cosigner_keypair(ctx, args.cosigner_keypair.as_deref())?;
    CoSignerCheck {
        provided: cosigner.as_ref().map(|keypair| keypair.pubkey()),
        scope: custom_ring_interface::COSIGN_TRANSFERS | custom_ring_interface::COSIGN_DEPOSITS,
        payment: Some(PolicyPayment {
            mint,
            amount: args.amount,
        }),
    }
    .check(ctx)?;
    let tree = transfer_tree(ctx.ring, &ctx.rpc)?;
    let sender = sender_keypair(ctx)?;
    // 2. Fund a persistent sender and move the deposited amount to the requested recipient.
    let session = Session::open(ctx, if mint == SOL_MINT { args.amount } else { 0 })?;
    // The recipient takes the whole amount, so the two deposits split it.
    let half = args.amount / 2;
    let sent = RingTransfer {
        ring: ctx.ring,
        payer: &session.authority,
        sender,
        deposits: [half, args.amount - half],
        recipient: args.to,
        amount: args.amount,
        tree,
        assets: &assets.registry,
        asset,
        cosigner: cosigner.as_ref().map(|keypair| keypair as &dyn Signer),
    }
    .send(session.env(ctx))?;
    line("to", args.to);
    line("amount", format_args!("{} base units", args.amount));
    line("mint", mint);
    line(
        "sender",
        format_args!("{}  saved in {}", sent.sender.pubkey(), SENDER_KEYPAIR_FILE),
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
pub(crate) struct Session {
    pub authority: solana_keypair::Keypair,
    pub ring_rpc: RingRpcClient,
    pub indexer: ZolanaIndexer,
    pub prover: zolana_client::ProverClient,
}

impl Session {
    pub fn open(ctx: &mut Context, deposited: u64) -> Result<Self, TransactError> {
        let needed = deposited
            .saturating_add(SENDER_FEE_BUDGET)
            .saturating_add(PAYER_FEE_BUDGET);
        let ring_rpc = ctx.ring_rpc();
        ring_rpc.check_serves(ctx.ring.program_id())?;
        let authority = ctx.authority_funded_for(needed)?;
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

/// The `list` member argument of a party.
fn owner_tag(party: &ShieldedKeypair) -> Result<Address, KeypairError> {
    Ok(Address::new_from_array(
        party.signing_pubkey().confidential_view_tag()?,
    ))
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
    ui::heading(
        Icon::Auditor,
        &format!("auditor sees slot {} at {signature}", opened.slot),
    );
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
        let enrol = policy_rules(self.ring, env.rpc)?
            .is_some_and(|rules| rules.referenced().contains(ListId::Allow));
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
            tree: transfer_tree(self.ring, env.rpc)?,
            assets: &assets,
            asset: DepositAsset::Sol,
            cosigner: self.cosigner,
        }
        .deposit(env.indexer, env.rpc)?;
        if enrol {
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
                asset: self.asset,
                amount,
                cosigner: self.cosigner,
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
        let fee = solana_system_interface::instruction::transfer(
            &this.payer.pubkey(),
            &sender.pubkey(),
            SENDER_FEE_BUDGET,
        );
        env.rpc.create_and_send_transaction(
            &[fee],
            this.payer.pubkey(),
            &[this.payer],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
        // 1. Windowed transfers need a registered record before proof preparation.
        if policy_rules(this.ring, rpc)?.is_some_and(|rules| rules.window_slots() != 0) {
            let outcome = Registration {
                ring: this.ring,
                sender: &sender,
                rpc,
                indexer: env.indexer,
                prover: env.prover,
            }
            .ensure()?;
            line("spend record", outcome.label());
        }

        let tree_id = custom_ring_sdk::tree_id(rpc, this.tree)?;
        let inputs = utxos
            .into_iter()
            .map(|utxo| SppProofInputUtxo::new(utxo, &sender).in_tree(tree_id))
            .collect();
        let mut transfer =
            ConfidentialTransfer::new(sender.shielded_address()?, inputs, sender.pubkey())
                .with_compact_change()
                .with_ring_program_id(this.ring.program_id())
                .with_output_tree_id(tree_id);
        transfer.send(&this.recipient, this.asset.mint(), this.amount)?;
        // 2. Bind the payment and any record successor to the same private transaction context.
        let prepared = transfer.prepare()?;
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: this.ring,
            sender: &sender,
            prepared,
        })
        .with_tree(this.tree)
        .with_assets(this.assets);
        if let Some(cosigner) = this.cosigner {
            transfer = transfer.with_cosigner(cosigner.pubkey());
        }
        let proven = transfer.prove(env)?;
        if proven.approval_required && this.cosigner.is_none() {
            return Err(TransactError::ApprovalNeedsCoSigner);
        }
        // 3. Submit with every required signer after the policy proof fixes the approval bit.
        let signers: Vec<&dyn Signer> = this.cosigner.into_iter().collect();
        let transact = TransactSend {
            payer: &sender,
            signers: &signers,
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

/// The pinned table, `None` for an audit-only ring.
fn policy_rules(ring: CustomRing, rpc: &SolanaRpc) -> Result<Option<RuleTable>, TransactError> {
    ring.read_policy_config(rpc)?
        .map(|config| policy_config_table(&config))
        .transpose()
        .map_err(|error| TransactError::PolicyMatch(Box::new(error)))
}

fn transfer_tree(ring: CustomRing, rpc: &SolanaRpc) -> Result<Address, TransactError> {
    let Some(config) = ring.read_policy_config(rpc)? else {
        return Ok(pda::tree(0));
    };
    let rules = policy_config_table(&config)
        .map_err(|error| TransactError::PolicyMatch(Box::new(error)))?;
    Ok(if rules.window_slots() != 0 {
        config.entries_tree
    } else {
        pda::tree(0)
    })
}

/// Checks CLI operation scope and known payment thresholds before public funding.
pub(crate) struct CoSignerCheck {
    pub provided: Option<Address>,
    pub scope: u8,
    pub payment: Option<PolicyPayment>,
}

/// Supplies the known mint outflow for a CLI payment's approval preflight.
pub(crate) struct PolicyPayment {
    pub mint: Address,
    pub amount: u64,
}

impl CoSignerCheck {
    pub fn check(self, ctx: &Context) -> Result<(), TransactError> {
        let configured = ctx.ring.read_cosigner(&ctx.rpc)?;
        let approval = if let Some(payment) = &self.payment {
            let asset = Member::asset(&payment.mint)?;
            policy_rules(ctx.ring, &ctx.rpc)?.is_some_and(|rules| {
                rules.velocity().iter().any(|row| {
                    row.asset == *asset.as_bytes()
                        && row.cosign_above != 0
                        && payment.amount > row.cosign_above
                })
            })
        } else {
            false
        };
        self.require(configured.as_ref(), approval)
    }

    fn require(
        self,
        configured: Option<&custom_ring_sdk::CustomRingCoSigner>,
        approval: bool,
    ) -> Result<(), TransactError> {
        let Some(configured) = configured else {
            return if approval {
                Err(TransactError::CoSignerNotConfigured)
            } else {
                Ok(())
            };
        };
        if let Some(found) = self.provided {
            if found != configured.signer {
                return Err(TransactError::WrongCoSigner {
                    expected: configured.signer,
                    found,
                });
            }
        }
        if (approval || configured.scope & self.scope != 0) && self.provided.is_none() {
            return Err(TransactError::ApprovalNeedsCoSigner);
        }
        Ok(())
    }
}

/// Not checked against the ring's scope, the program decides.
pub(crate) fn cosigner_keypair(
    ctx: &Context,
    path: Option<&Path>,
) -> Result<Option<solana_keypair::Keypair>, FileError> {
    path.map(|path| file::read_keypair(&ctx.project_path(path)))
        .transpose()
}

/// Kept between runs, earlier change stays spendable with it.
fn sender_keypair(ctx: &Context) -> Result<ShieldedKeypair, TransactError> {
    Ok(ShieldedKeypair::from_keypair(&sender_keypair_file(ctx)?)?)
}

pub(crate) fn sender_keypair_file(ctx: &Context) -> Result<solana_keypair::Keypair, FileError> {
    file::read_or_create_keypair(&ctx.project_path(Path::new(SENDER_KEYPAIR_FILE)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_sdk::{
        CustomRingCoSigner, COSIGN_DEPOSITS, COSIGN_TRANSFERS, COSIGN_WITHDRAWALS,
    };

    #[test]
    fn approval_is_checked_before_funding_for_deposits_and_transfers() {
        let signer = Address::new_from_array([1; 32]);
        let mut configured = CustomRingCoSigner {
            signer,
            scope: COSIGN_DEPOSITS,
            thresholds: vec![],
        };
        let check = |provided| CoSignerCheck {
            provided,
            scope: COSIGN_DEPOSITS | COSIGN_TRANSFERS,
            payment: None,
        };
        assert!(matches!(
            check(None).require(Some(&configured), false),
            Err(TransactError::ApprovalNeedsCoSigner)
        ));
        assert!(check(Some(signer))
            .require(Some(&configured), false)
            .is_ok());
        assert!(matches!(
            check(Some(Address::default())).require(Some(&configured), false),
            Err(TransactError::WrongCoSigner { .. })
        ));
        configured.scope = COSIGN_WITHDRAWALS;
        assert!(check(None).require(Some(&configured), false).is_ok());
        assert!(matches!(
            check(None).require(Some(&configured), true),
            Err(TransactError::ApprovalNeedsCoSigner)
        ));
        assert!(matches!(
            check(None).require(None, true),
            Err(TransactError::CoSignerNotConfigured)
        ));
        assert!(check(None).require(None, false).is_ok());
    }
}
