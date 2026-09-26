use std::{
    path::Path,
    time::{Duration, Instant},
};

use custom_ring_sdk::{
    policy_config_table, AccountReadError, CoSignScope, CustomRing, CustomRingCoSigner,
    CustomRingTransfer, CustomRingTransferInput, DepositAsset, DepositError,
    DepositProofEnvironment, EntryProofEnvironment, PolicyConfig, PolicyMatchError, RingDeposit,
    RingDepositReceipt, SendError, TransactSend, TransferError, TransferProofEnvironment,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::pda;
use zolana_keypair::{shielded::ShieldedAddress, KeypairError, ShieldedKeypair};
use zolana_ring_client::{ReaderKey, ReaderKeyError};
use zolana_ring_policy::{EntryState, ListId, Member, MemberError, RuleTable};
use zolana_transaction::{
    instructions::transact::{canonical_shape, ConfidentialTransaction},
    TransactionError, Utxo, WalletUtxo, SOL_MINT,
};

use crate::{
    assets::{self, AssetError, DepositFunding},
    error::boxed_from,
    file::{self, FileError},
    key::{KeyEnrolment, KeyError},
    line,
    list::{EntryMutation, ListError},
    ring_rpc::{RingRpcClient, RingRpcClientError, TransactionLookup},
    spend::{Registration, SpendError},
    ui::{self, Icon},
    Context, ContextError, TransactArgs, TransferArgs, SENDER_KEYPAIR_FILE,
};

/// Covers the sender's lookup table rent and fees.
pub(crate) const SENDER_FEE_BUDGET: u64 = 20_000_000;
/// Lookup table rent, the deposit and transact fees.
pub(crate) const PAYER_FEE_BUDGET: u64 = 10_000_000;
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// A deposit and a transfer land in one command.
const DEPOSIT_TRANSFER_SCOPE: CoSignScope =
    match CoSignScope::new(CoSignScope::TRANSFERS.bits() | CoSignScope::DEPOSITS.bits()) {
        Some(scope) => scope,
        None => unreachable!(),
    };

#[must_use]
pub struct DemoTransfer<'a> {
    pub ring: CustomRing,
    pub payer: &'a dyn Signer,
    pub sender: ShieldedKeypair,
    pub amount: u64,
    pub cosigner: Option<&'a dyn Signer>,
    pub rules: Option<&'a RingRules>,
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
    asset: DepositAsset,
    cosigner: Option<&'a dyn Signer>,
    rules: Option<&'a RingRules>,
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

/// The pinned policy, `None` for an audit-only ring.
pub struct RingRules {
    config: PolicyConfig,
    rules: RuleTable,
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
    #[error("amount {amount} does not split across the two deposits a ring transfer input_utxos")]
    AmountTooSmall { amount: u64 },
    #[error(transparent)]
    Spend(Box<SpendError>),
    #[error(transparent)]
    Key(Box<KeyError>),
    #[error("the transfer needs the co-signer's approval, pass --cosigner-keypair")]
    ApprovalNeedsCoSigner,
    #[error("the configured co-signer is {expected}, not {found}")]
    WrongCoSigner { expected: Address, found: Address },
    #[error("the policy needs approval but no co-signer is configured")]
    CoSignerNotConfigured,
    #[error(transparent)]
    Asset(Box<AssetError>),
}

boxed_from!(TransactError {
    Asset(AssetError),
    Spend(SpendError),
    Key(KeyError),
    List(ListError),
    PolicyMatch(PolicyMatchError),
});

pub fn run(ctx: &mut Context, args: TransactArgs) -> Result<(), TransactError> {
    let rules = RingRules::read(ctx.ring, &ctx.rpc)?;
    let cosigner = CoSignerCheck {
        keypair: args.cosigner_keypair.as_deref(),
        scope: DEPOSIT_TRANSFER_SCOPE,
        payment: Some(PolicyPayment {
            mint: SOL_MINT,
            outflow: args.amount,
            rules: rules.as_ref().map(|rules| &rules.rules),
        }),
    }
    .load(ctx)?;
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
        rules: rules.as_ref(),
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
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let assets = assets::resolve(&ctx.rpc, mint)?;
    let payer = ctx.config.config_authority().map_err(ContextError::from)?;
    let asset = assets.deposit(
        &ctx.rpc,
        DepositFunding {
            payer: payer.pubkey(),
            token_account: args.token_account,
            amount: args.amount,
        },
    )?;
    let rules = RingRules::read(ctx.ring, &ctx.rpc)?;
    let sender = sender_keypair(ctx)?;
    let cosigner = CoSignerCheck {
        keypair: args.cosigner_keypair.as_deref(),
        scope: DEPOSIT_TRANSFER_SCOPE,
        payment: Some(
            RingPayment {
                mint,
                amount: args.amount,
                sender: &sender,
                recipient: &args.to,
                rules: rules.as_ref().map(|rules| &rules.rules),
            }
            .policy()?,
        ),
    }
    .load(ctx)?;
    let tree = pda::tree(0);
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
        asset,
        cosigner: cosigner.as_ref().map(|keypair| keypair as &dyn Signer),
        rules: rules.as_ref(),
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
struct Session {
    authority: Keypair,
    ring_rpc: RingRpcClient,
    indexer: ZolanaIndexer,
    prover: zolana_client::ProverClient,
}

impl Session {
    fn open(ctx: &mut Context, deposited: u64) -> Result<Self, TransactError> {
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
    reader: &Keypair,
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
        let enrol = self
            .rules
            .is_some_and(|rules| rules.rules.referenced().contains(ListId::Allow));
        // The demo deposits the amount twice and keeps the change, so the
        // sender's balance shows in the auditor's view next to the payment.
        let deposited = RingTransfer {
            ring: self.ring,
            payer: self.payer,
            sender: self.sender,
            deposits: [self.amount; 2],
            recipient: recipient.shielded_address()?,
            amount: self.amount,
            tree: pda::tree(0),
            asset: DepositAsset::Sol,
            cosigner: self.cosigner,
            rules: self.rules,
        }
        .deposit(&env)?;
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
        self.deposit(&env)?.prove_and_send(env)
    }

    /// Two deposits fill both input slots of IN2_OUT2, the compact change and
    /// the recipient fill the outputs.
    fn deposit(
        self,
        env: &TransferProofEnvironment<'_, ZolanaIndexer, SolanaRpc>,
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
            .send(DepositProofEnvironment {
                indexer: env.indexer,
                rpc: env.rpc,
                prover: env.prover,
            })?;
            utxos.push(utxo);
            deposits.push(signature);
        }
        // Photon learns a tree from its first indexed transaction.
        if let Some(last) = deposits.last() {
            wait_for_indexed_transaction(env.indexer, *last)?;
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
            .rules
            .and_then(|rules| rules.config.source_for(ListId::Allow))
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
        if let Some(rules) = this.rules.filter(|rules| rules.windowed()) {
            let outcome = Registration {
                ring: this.ring,
                sender: &sender,
                config: &rules.config,
                rpc,
                indexer: env.indexer,
                prover: env.prover,
            }
            .ensure()?;
            line("spend record", outcome.label());
        }
        let enrolled = KeyEnrolment {
            ring: this.ring,
            member: &sender,
        }
        .ensure(TransferProofEnvironment {
            indexer: env.indexer,
            rpc,
            prover: env.prover,
        })?;
        line("member key", enrolled.label());

        let tree_id = custom_ring_sdk::tree_id(rpc, this.tree)?;
        let nullifier_pubkey = sender.nullifier_key.pubkey()?;
        let hashes = utxos
            .iter()
            .map(|utxo| utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id))
            .collect::<Result<Vec<_>, _>>()?;
        let proofs = env
            .indexer
            .get_merkle_proofs(this.tree, hashes, None)?
            .proofs;
        let inputs = utxos
            .into_iter()
            .map(|utxo| {
                let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)?;
                let state = proofs
                    .iter()
                    .find(|proof| proof.leaf == utxo_hash)
                    .ok_or_else(|| ClientError::Rpc("missing deposited input proof".into()))?;
                let nullifier = sender.nullifier_key.nullifier(&utxo_hash, &utxo.blinding)?;
                Ok(WalletUtxo {
                    utxo,
                    utxo_hash,
                    nullifier,
                    nullifier_pubkey,
                    tree_id,
                    leaf_index: state.leaf_index,
                    data_hash: None,
                    ring_data_hash: None,
                    slot: 0,
                    tx_signature: Signature::default(),
                    slot_index: 0,
                })
            })
            .collect::<Result<Vec<_>, TransactError>>()?;
        let shape = canonical_shape(inputs.len(), 2)?;
        let mut transfer = ConfidentialTransaction::new_with_ring(
            inputs,
            sender.pubkey(),
            this.ring.program_id(),
        )?
        .with_output_tree_id(tree_id)?;
        if this.asset.mint() == zolana_transaction::SOL_MINT {
            transfer.transfer_sol(&this.recipient, this.amount)?;
        } else {
            transfer.transfer(&this.recipient, this.asset.mint(), this.amount)?;
        }
        transfer.pad_utxos(shape, &sender.shielded_address()?)?;
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: this.ring,
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: transfer,
        });
        if let Some(cosigner) = this.cosigner {
            transfer = transfer.with_cosigner(cosigner.pubkey());
        }
        let proven = transfer.prove(env)?;
        if proven.approval_required && this.cosigner.is_none() {
            return Err(TransactError::ApprovalNeedsCoSigner);
        }
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

impl RingRules {
    pub fn read(ring: CustomRing, rpc: &SolanaRpc) -> Result<Option<Self>, TransactError> {
        ring.read_policy_config(rpc)?
            .map(|config| policy_config_table(&config).map(|rules| Self { config, rules }))
            .transpose()
            .map_err(TransactError::from)
    }

    fn windowed(&self) -> bool {
        self.rules.window_slots() != 0
    }
}

pub(crate) struct CoSignerCheck<'a> {
    pub keypair: Option<&'a Path>,
    pub scope: CoSignScope,
    pub payment: Option<PolicyPayment<'a>>,
}

pub(crate) struct PolicyPayment<'a> {
    pub mint: Address,
    pub outflow: u64,
    pub rules: Option<&'a RuleTable>,
}

/// Resolves requested ring payments into the sender outflow checked by policy.
#[must_use]
struct RingPayment<'a> {
    mint: Address,
    amount: u64,
    sender: &'a ShieldedKeypair,
    recipient: &'a ShieldedAddress,
    rules: Option<&'a RuleTable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    Required,
    NotRequired,
}

struct Requirement<'a> {
    configured: Option<&'a CustomRingCoSigner>,
    provided: Option<Address>,
    approval: Approval,
}

impl CoSignerCheck<'_> {
    pub fn load(self, ctx: &Context) -> Result<Option<Keypair>, TransactError> {
        let cosigner = self
            .keypair
            .map(|path| file::read_keypair(&ctx.project_path(path)))
            .transpose()?;
        let configured = ctx.ring.read_cosigner(&ctx.rpc)?;
        let approval = match &self.payment {
            Some(payment) => payment.approval()?,
            None => Approval::NotRequired,
        };
        Requirement {
            configured: configured.as_ref(),
            provided: cosigner.as_ref().map(Signer::pubkey),
            approval,
        }
        .check(self.scope)?;
        Ok(cosigner)
    }
}

impl<'a> RingPayment<'a> {
    fn policy(self) -> Result<PolicyPayment<'a>, KeypairError> {
        // 1. Same-owner outputs remain inside the ring and charge no policy
        // outflow.
        let same_owner = self.sender.signing_pubkey().owner_proof_input_hash()?
            == self.recipient.signing_pubkey.owner_proof_input_hash()?;
        Ok(PolicyPayment {
            mint: self.mint,
            outflow: if same_owner { 0 } else { self.amount },
            rules: self.rules,
        })
    }
}

impl PolicyPayment<'_> {
    fn approval(&self) -> Result<Approval, TransactError> {
        let asset = Member::asset(&self.mint)?;
        let demanded = self.rules.is_some_and(|rules| {
            rules.velocity().iter().any(|row| {
                row.asset == *asset.as_bytes()
                    && row.cosign_above != 0
                    && self.outflow > row.cosign_above
            })
        });
        Ok(if demanded {
            Approval::Required
        } else {
            Approval::NotRequired
        })
    }
}

impl Requirement<'_> {
    fn check(self, scope: CoSignScope) -> Result<(), TransactError> {
        let Some(configured) = self.configured else {
            return match self.approval {
                Approval::Required => Err(TransactError::CoSignerNotConfigured),
                Approval::NotRequired => Ok(()),
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
        let demanded = self.approval == Approval::Required || configured.scope.intersects(scope);
        if demanded && self.provided.is_none() {
            return Err(TransactError::ApprovalNeedsCoSigner);
        }
        Ok(())
    }
}

/// Kept between runs, earlier change stays spendable with it.
fn sender_keypair(ctx: &Context) -> Result<ShieldedKeypair, TransactError> {
    Ok(ShieldedKeypair::from_keypair(&sender_keypair_file(ctx)?)?)
}

pub(crate) fn sender_keypair_file(ctx: &Context) -> Result<Keypair, FileError> {
    file::read_or_create_keypair(&ctx.project_path(Path::new(SENDER_KEYPAIR_FILE)))
}

pub(crate) fn signers<'a>(
    primary: &'a dyn Signer,
    cosigner: Option<&'a dyn Signer>,
) -> Vec<&'a dyn Signer> {
    std::iter::once(primary).chain(cosigner).collect()
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

    #[test]
    fn blanket_scope_and_private_approval_require_the_configured_signer() {
        let signer = Address::new_from_array([1; 32]);
        let mut configured = CustomRingCoSigner {
            signer,
            scope: CoSignScope::DEPOSITS,
            thresholds: vec![],
        };
        let check = |configured: Option<&CustomRingCoSigner>, provided, approval| {
            Requirement {
                configured,
                provided,
                approval,
            }
            .check(DEPOSIT_TRANSFER_SCOPE)
        };
        assert!(matches!(
            check(Some(&configured), None, Approval::NotRequired),
            Err(TransactError::ApprovalNeedsCoSigner)
        ));
        assert!(check(Some(&configured), Some(signer), Approval::NotRequired).is_ok());
        assert!(matches!(
            check(
                Some(&configured),
                Some(Address::default()),
                Approval::NotRequired
            ),
            Err(TransactError::WrongCoSigner { .. })
        ));
        configured.scope = CoSignScope::WITHDRAWALS;
        assert!(check(Some(&configured), None, Approval::NotRequired).is_ok());
        assert!(matches!(
            check(Some(&configured), None, Approval::Required),
            Err(TransactError::ApprovalNeedsCoSigner)
        ));
        assert!(matches!(
            check(None, None, Approval::Required),
            Err(TransactError::CoSignerNotConfigured)
        ));
        assert!(check(None, None, Approval::NotRequired).is_ok());
    }

    #[test]
    fn self_transfer_has_no_private_outflow_but_keeps_blanket_scope_checks() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let rules = RuleTable::builder()
            .velocity(&[zolana_ring_policy::VelocityRow {
                asset: *Member::asset(&SOL_MINT).unwrap().as_bytes(),
                cap: 0,
                cosign_above: 10,
            }])
            .build();
        let mut recipient = sender.shielded_address().unwrap();
        recipient.viewing_pubkey = zolana_keypair::ViewingKey::new().pubkey();
        recipient.nullifier_pubkey = zolana_keypair::NullifierKey::from_secret([7; 31])
            .pubkey()
            .unwrap();
        let payment = RingPayment {
            mint: SOL_MINT,
            amount: 11,
            sender: &sender,
            recipient: &recipient,
            rules: Some(&rules),
        }
        .policy()
        .unwrap();
        assert_eq!(payment.outflow, 0);
        assert_eq!(payment.approval().unwrap(), Approval::NotRequired);
        let signer = Address::new_from_array([1; 32]);
        for (scope, required) in [
            (CoSignScope::WITHDRAWALS, false),
            (CoSignScope::DEPOSITS, true),
            (CoSignScope::TRANSFERS, true),
        ] {
            let configured = CustomRingCoSigner {
                signer,
                scope,
                thresholds: vec![],
            };
            let check = |provided| {
                Requirement {
                    configured: Some(&configured),
                    provided,
                    approval: payment.approval().unwrap(),
                }
                .check(DEPOSIT_TRANSFER_SCOPE)
            };
            assert_eq!(check(None).is_err(), required);
            assert!(check(Some(signer)).is_ok());
            assert!(matches!(
                check(Some(Address::default())),
                Err(TransactError::WrongCoSigner { .. })
            ));
        }
    }

    #[test]
    fn a_different_owner_charges_the_payment_and_uses_a_strict_nonzero_threshold() {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let recipient = ShieldedKeypair::new_ed25519()
            .unwrap()
            .shielded_address()
            .unwrap();
        for (threshold, amount, approval) in [
            (10, 10, Approval::NotRequired),
            (10, 11, Approval::Required),
            (0, u64::MAX, Approval::NotRequired),
        ] {
            let rules = RuleTable::builder()
                .velocity(&[zolana_ring_policy::VelocityRow {
                    asset: *Member::asset(&SOL_MINT).unwrap().as_bytes(),
                    cap: u64::MAX,
                    cosign_above: threshold,
                }])
                .build();
            let payment = RingPayment {
                mint: SOL_MINT,
                amount,
                sender: &sender,
                recipient: &recipient,
                rules: Some(&rules),
            }
            .policy()
            .unwrap();
            assert_eq!(payment.outflow, amount);
            assert_eq!(payment.approval().unwrap(), approval);
        }
    }

    #[test]
    fn the_program_codes_the_submission_retries_on_are_pinned() {
        use custom_ring_program::CustomRingError;
        assert_eq!(CustomRingError::StaleKeyRegistryRoot as u32, 8161);
        assert_eq!(CustomRingError::ProofVerificationFailed as u32, 8101);
    }
}
