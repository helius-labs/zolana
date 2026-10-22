//! `transact`, `transfer` and `deposit`, audited deposits and the ring transfers that spend them.

use std::str::FromStr;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::{cosign::CoSignDemand, AnonymousSpend, RingProgramConfig, RingRail};
use custom_ring_sdk::{
    shape_keyed, AnonymousMove, AnonymousPayment, CoSignScope, CustomRingConfig,
    CustomRingTransfer, CustomRingTransferInput, DepositAsset, DepositRecipient, EntrySpend,
    EscrowedRecipients, ListRegistry, PendingFirstContact, RingDeposit, RingDepositReceipt,
    RingMode, RingPayment,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_event_parser::indexed_events_from_instruction_groups;
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::{
    ring_address::RING_PAYMENT_SCHEME, shielded::ShieldedAddress, PublicKey, RingAddress,
    RingPaymentRequest, ShieldedKeypair,
};
use zolana_ring_client::{
    rpc::{DecryptedOutputKind, ReadTarget},
    ReaderKey,
};
use zolana_ring_policy::{ListId, Member, OutflowLimit};
use zolana_transaction::{
    instructions::transact::{
        canonical_shape, ConfidentialTransaction, Shape, MAX_SPEND_INPUTS, SPP_SUPPORTED_SHAPES,
    },
    select_spend_where, AssetRegistry, SpendableDecryptionResult, WalletUtxo, SOL_MINT,
};

use crate::{
    address, assets,
    audit::OpenedSlot,
    file,
    fund::TopUp,
    line,
    list::{ListChange, ListUpdate, Subject},
    macros::named_enum,
    member::KeyEnrolment,
    merge::carries_no_data,
    policy, records,
    ui::{self, icon},
    wallet::{AnonymousRingStore, WalletScan},
    Context, CosignerArg, DepositArgs, TransactArgs, TransferArgs, Trust, DEFAULT_TRANSACT_AMOUNT,
    SENDER_KEYPAIR_FILE,
};

/// Covers the sender's registrations and fees.
pub(crate) const SENDER_FEE_BUDGET: u64 = 20_000_000;
/// The deposit and transact fees.
pub(crate) const PAYER_FEE_BUDGET: u64 = 10_000_000;

named_enum! {
    pub enum Funding("funding") {
        Deposit = "deposit",
        Held = "held",
    }
}

named_enum! {
    pub enum EntrySpendName("entry spend") {
        Refuse = "refuse",
        Allow = "allow",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipient {
    Shielded(ShieldedAddress),
    Ring(Box<RingPaymentRequest>),
}

pub(crate) struct CoSigner {
    keypair: Option<Keypair>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Demand {
    Deposit,
    /// A transfer under no co-sign bound, merges and delegate moves included.
    Transfer,
    /// A transfer past a co-sign bound of the pinned policy.
    Approval,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Payments {
    mint: Address,
    payees: Payees,
    outputs: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Payment<T> {
    to: T,
    amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Payees {
    Confidential(Vec<Payment<ShieldedAddress>>),
    Anonymous {
        ring: Vec<Payment<RingAddress>>,
        default_ring: Vec<Payment<ShieldedAddress>>,
        entry: EntrySpend,
    },
}

#[must_use]
struct PaymentPlan<'a> {
    recipients: &'a [Recipient],
    amount: Option<u64>,
    mint: Option<Address>,
    outputs: Option<usize>,
    default_ring: bool,
    entry: EntrySpend,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Outflow {
    mint: Address,
    amount: u64,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Requirement {
    configured: Option<Address>,
    demanded: Option<Address>,
}

/// The demo parties a table referencing `Allow` refuses until their records carry it.
#[must_use]
struct AllowEnrolment<'a> {
    authority: &'a Keypair,
    parties: &'a [(&'a str, &'a ShieldedKeypair)],
}

#[must_use]
struct Deposit<'a> {
    payer: &'a Keypair,
    sender: &'a ShieldedKeypair,
    config: &'a CustomRingConfig,
    asset: DepositAsset,
    amount: u64,
    cosigner: Option<&'a (dyn Signer + Sync)>,
}

#[must_use]
struct Transfer<'a> {
    config: &'a CustomRingConfig,
    registry: &'a AssetRegistry,
    payer: &'a Keypair,
    sender: &'a ShieldedKeypair,
    payments: &'a Payments,
    cosigner: Option<&'a (dyn Signer + Sync)>,
}

enum Inputs<'a> {
    Deposits {
        asset: DepositAsset,
        amounts: [u64; 2],
        cosigner: Option<&'a (dyn Signer + Sync)>,
    },
    Held(Vec<WalletUtxo>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spendable {
    RingOnly,
    WithDefaultRing,
    /// The anonymous prover refuses ring and default-ring notes in one spend.
    DefaultRingOnly,
}

struct Sent {
    deposits: Vec<Signature>,
    transact: Signature,
}

#[must_use]
struct FirstContacts<'a> {
    store: &'a AnonymousRingStore,
    signature: Signature,
    pending: &'a [PendingFirstContact],
}

pub fn run(ctx: &Context, args: TransactArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    let program = ctx.ring.program_id();
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    let recipient = ShieldedKeypair::new_ed25519()?;
    let to = match config.mode {
        RingMode::Anonymous => Recipient::Ring(Box::new(RingPaymentRequest::new(
            address::ring_address(&recipient, program, 0)?,
        ))),
        RingMode::Off | RingMode::Registry => Recipient::Shielded(recipient.shielded_address()?),
    };
    let payments = PaymentPlan::new(&[to])
        .with_amount(args.amount)
        .resolve(config.mode, program)?;
    let registry = assets::resolve(ctx.rpc(), SOL_MINT)?.registry;
    let cosigner = CoSigner::read(ctx, &args.cosigner)?;
    let demand = payments.outflow(&sender.signing_pubkey())?.demand(ctx)?;
    let inputs = Inputs::Deposits {
        asset: DepositAsset::Sol,
        amounts: [args.amount; 2],
        cosigner: cosigner.sign(&config, Demand::Deposit)?,
    };
    let transfer = Transfer {
        config: &config,
        registry: &registry,
        payer: ctx.member_payer(config.mode, sender.pubkey())?,
        sender: &sender,
        payments: &payments,
        cosigner: cosigner.sign(&config, demand)?,
    };
    payments.fits(&inputs)?;
    ctx.ring_rpc().check_serves(program)?;
    let reader = ReaderKey::ed25519(ctx.authority()?.pubkey())?;
    ensure!(
        granted(ctx, &reader)?,
        "reader {reader} is not granted, run `zolana-ring reader grant {reader}` first"
    );
    let authority = ctx.funded_authority()?;
    let parties = [("sender", &sender), ("recipient", &recipient)];
    let queued = (config.mode == RingMode::Registry)
        .then(|| {
            KeyEnrolment {
                funder: authority,
                members: &[&sender, &recipient],
            }
            .queue(ctx)
        })
        .transpose()?
        .flatten();
    AllowEnrolment {
        authority,
        parties: &parties,
    }
    .send(ctx)?;
    if let Some(queued) = queued {
        queued.apply(&ctx.zolana, authority)?;
        line("member keys", "applied");
    }
    transfer.fund(ctx, inputs.drawn_lamports())?;
    let sent = transfer.send(ctx, inputs)?;
    for (party, keys) in parties {
        let viewing = hex::encode(keys.viewing_pubkey().as_bytes());
        line(
            party,
            format_args!("{}  viewing pk {viewing}", keys.pubkey()),
        );
    }
    line("sender tag", owner_tag(&sender.shielded_address()?)?);
    line("recipient tag", owner_tag(&recipient.shielded_address()?)?);
    print_signatures(ctx, &sent)?;
    read_back(ctx, authority, sent.transact)
}

/// Every recipient is checked against the ring's mode before anything is deposited.
pub fn run_transfer(ctx: &Context, args: TransferArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    let payments = PaymentPlan::of(&args).resolve(config.mode, ctx.ring.program_id())?;
    let total = payments.total()?;
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    let cosigner = CoSigner::read(ctx, &args.cosigner)?;
    let demand = payments.outflow(&sender.signing_pubkey())?.demand(ctx)?;
    let authority = ctx.authority()?;
    let resolved = assets::resolve(ctx.rpc(), payments.mint)?;
    let transfer = Transfer {
        config: &config,
        registry: &resolved.registry,
        payer: ctx.member_payer(config.mode, sender.pubkey())?,
        sender: &sender,
        payments: &payments,
        cosigner: cosigner.sign(&config, demand)?,
    };
    let inputs = match args.funding {
        Funding::Deposit => {
            ensure!(
                total >= 2,
                "amount {total} does not split across the two deposits a ring transfer spends"
            );
            let deposit_cosigner = cosigner.sign(&config, Demand::Deposit)?;
            let payer = transfer.payer.pubkey();
            let asset = resolved.deposit(ctx.rpc(), payer, args.token_account, total)?;
            let half = total / 2;
            Inputs::Deposits {
                asset,
                amounts: [half, total - half],
                cosigner: deposit_cosigner,
            }
        }
        Funding::Held => {
            ensure!(
                args.token_account.is_none(),
                "--token-account funds a deposit, `--funding held` deposits nothing"
            );
            Inputs::Held(transfer.held_utxos(ctx)?)
        }
    };
    payments.fits(&inputs)?;
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;
    if config.mode == RingMode::Registry {
        payments.check_escrowed(ctx, &sender)?;
        KeyEnrolment {
            funder: ctx.funded_authority()?,
            members: &[&sender],
        }
        .ensure(ctx)?;
    }
    transfer.fund(ctx, inputs.drawn_lamports())?;
    let sent = transfer.send(ctx, inputs)?;
    for payment in payments.each() {
        line(
            "to",
            format_args!("{}  {} base units", payment.to, payment.amount),
        );
    }
    line("mint", payments.mint);
    let saved = sender.pubkey();
    line(
        "sender",
        format_args!("{saved}  saved in {SENDER_KEYPAIR_FILE}"),
    );
    print_signatures(ctx, &sent)?;
    // Reading the transfer back is a courtesy, the payment is already on chain.
    let reader = ReaderKey::ed25519(authority.pubkey())?;
    if !granted(ctx, &reader)? {
        println!("auditor view skipped, `zolana-ring reader grant {reader}` lets it read the ring");
        return Ok(());
    }
    read_back(ctx, authority, sent.transact)
}

pub fn run_deposit(ctx: &Context, args: DepositArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let cosigner = CoSigner::read(ctx, &args.cosigner)?;
    let deposit_cosigner = cosigner.sign(&config, Demand::Deposit)?;
    let sender = ShieldedKeypair::from_keypair(&ctx.sender()?)?;
    let payer = ctx.member_payer(config.mode, sender.pubkey())?;
    let asset = assets::resolve(ctx.rpc(), mint)?.deposit(
        ctx.rpc(),
        payer.pubkey(),
        args.token_account,
        args.amount,
    )?;
    if config.mode == RingMode::Registry {
        KeyEnrolment {
            funder: ctx.funded_authority()?,
            members: &[&sender],
        }
        .ensure(ctx)?;
    }
    let drawn = deposit_lamports(asset, args.amount);
    ctx.fund(payer.pubkey(), drawn.saturating_add(PAYER_FEE_BUDGET))?;
    let receipt = Deposit {
        payer,
        sender: &sender,
        config: &config,
        asset,
        amount: args.amount,
        cosigner: deposit_cosigner,
    }
    .send(ctx)?;
    line("deposit", receipt.signature);
    line("amount", format_args!("{} base units", args.amount));
    line("mint", mint);
    line(
        "sender",
        format_args!("{}  saved in {SENDER_KEYPAIR_FILE}", sender.pubkey()),
    );
    Ok(())
}

impl FromStr for Recipient {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        if text.starts_with(RING_PAYMENT_SCHEME) {
            return text
                .parse()
                .map(|request| Self::Ring(Box::new(request)))
                .map_err(|error: zolana_keypair::KeypairError| error.to_string());
        }
        text.parse()
            .map(Self::Shielded)
            .map_err(|_| format!("{text} is neither a shielded address nor a `zolana:` request"))
    }
}

impl From<EntrySpendName> for EntrySpend {
    fn from(name: EntrySpendName) -> Self {
        match name {
            EntrySpendName::Refuse => Self::Refuse,
            EntrySpendName::Allow => Self::Allow,
        }
    }
}

impl<'a> PaymentPlan<'a> {
    fn new(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            amount: None,
            mint: None,
            outputs: None,
            default_ring: false,
            entry: EntrySpend::Refuse,
        }
    }

    fn of(args: &'a TransferArgs) -> Self {
        let mut plan = Self::new(&args.to).with_entry_spend(args.entry_spend.into());
        if let Some(amount) = args.amount {
            plan = plan.with_amount(amount);
        }
        if let Some(mint) = args.mint {
            plan = plan.with_mint(mint.0);
        }
        if let Some(outputs) = args.outputs {
            plan = plan.with_outputs(outputs);
        }
        if args.default_ring {
            plan = plan.with_default_ring();
        }
        plan
    }

    fn with_amount(self, amount: u64) -> Self {
        Self {
            amount: Some(amount),
            ..self
        }
    }

    fn with_mint(self, mint: Address) -> Self {
        Self {
            mint: Some(mint),
            ..self
        }
    }

    fn with_outputs(self, outputs: usize) -> Self {
        Self {
            outputs: Some(outputs),
            ..self
        }
    }

    /// An anonymous ring pays each shielded recipient a default-ring note.
    fn with_default_ring(self) -> Self {
        Self {
            default_ring: true,
            ..self
        }
    }

    fn with_entry_spend(self, entry: EntrySpend) -> Self {
        Self { entry, ..self }
    }

    /// A flag that differs from a request's amount or mint is refused.
    fn resolve(self, mode: RingMode, ring: Address) -> Result<Payments> {
        let requests = self
            .recipients
            .iter()
            .filter_map(|recipient| match recipient {
                Recipient::Ring(request) => Some(request),
                Recipient::Shielded(_) => None,
            });
        let requested_mint = requests.clone().find_map(|request| request.mint);
        let mint = self.mint.or(requested_mint).unwrap_or(SOL_MINT);
        if let Some(asked) = requests
            .clone()
            .find_map(|request| request.mint.filter(|asked| *asked != mint))
        {
            bail!("a request asks for mint {asked}, the transfer moves {mint}");
        }
        let amount = |asked: Option<u64>| -> Result<u64> {
            let amount = match (asked, self.amount) {
                (Some(asked), Some(given)) if asked != given => {
                    bail!("a request asks for {asked} base units, --amount names {given}")
                }
                (Some(asked), _) | (None, Some(asked)) => asked,
                (None, None) => DEFAULT_TRANSACT_AMOUNT,
            };
            ensure!(amount > 0, "a payment moves a nonzero amount");
            Ok(amount)
        };
        let payees = match mode {
            RingMode::Anonymous => {
                let (mut ring_payees, mut default_ring) = (Vec::new(), Vec::new());
                for recipient in self.recipients {
                    match recipient {
                        Recipient::Ring(request) => {
                            let to = &request.address;
                            ensure!(
                                to.ring_program_id == ring,
                                "the address pays ring {}, the transfer runs in {ring}",
                                to.ring_program_id
                            );
                            ring_payees.push(Payment {
                                to: to.clone(),
                                amount: amount(request.amount)?,
                            });
                        }
                        Recipient::Shielded(address) if self.default_ring => {
                            default_ring.push(Payment {
                                to: *address,
                                amount: amount(None)?,
                            });
                        }
                        Recipient::Shielded(address) => bail!(
                            "an anonymous ring pays a `zolana:` ring address, not shielded address {address}, `--default-ring` pays it a default-ring note"
                        ),
                    }
                }
                Payees::Anonymous {
                    ring: ring_payees,
                    default_ring,
                    entry: self.entry,
                }
            }
            RingMode::Off | RingMode::Registry if self.default_ring => {
                bail!("`--default-ring` pays out of an anonymous ring, ring {ring} is confidential")
            }
            RingMode::Off | RingMode::Registry => {
                match self.entry {
                    EntrySpend::Refuse => {}
                    EntrySpend::Allow => bail!(
                        "`--entry-spend` gates the default-ring notes an anonymous ring spends, ring {ring} is confidential"
                    ),
                }
                Payees::Confidential(
                    self.recipients
                        .iter()
                        .map(|recipient| match recipient {
                            Recipient::Shielded(address) => Ok(Payment {
                                to: *address,
                                amount: amount(None)?,
                            }),
                            Recipient::Ring(_) => bail!(
                                "a `zolana:` address pays an anonymous ring, ring {ring} is confidential"
                            ),
                        })
                        .collect::<Result<_>>()?,
                )
            }
        };
        Ok(Payments {
            mint,
            payees,
            outputs: self.outputs,
        })
    }
}

impl Payments {
    /// Each recipient's shielded keys, a ring address names its member's keys.
    fn each(&self) -> Vec<Payment<&ShieldedAddress>> {
        match &self.payees {
            Payees::Confidential(payees) => payees
                .iter()
                .map(|payment| Payment {
                    to: &payment.to,
                    amount: payment.amount,
                })
                .collect(),
            Payees::Anonymous {
                ring, default_ring, ..
            } => ring
                .iter()
                .map(|payment| Payment {
                    to: &payment.to.recipient,
                    amount: payment.amount,
                })
                .chain(default_ring.iter().map(|payment| Payment {
                    to: &payment.to,
                    amount: payment.amount,
                }))
                .collect(),
        }
    }

    fn total(&self) -> Result<u64> {
        sum(&self.each())
    }

    /// A payment to the owner's own signing key stays inside the ring.
    fn to_others(&self, owner: &PublicKey) -> Result<Vec<Payment<&ShieldedAddress>>> {
        let own = owner.owner_proof_input_hash()?;
        let mut others = Vec::new();
        for payment in self.each() {
            if payment.to.signing_pubkey.owner_proof_input_hash()? != own {
                others.push(payment);
            }
        }
        Ok(others)
    }

    fn outflow(&self, owner: &PublicKey) -> Result<Outflow> {
        Ok(Outflow {
            mint: self.mint,
            amount: sum(&self.to_others(owner)?)?,
        })
    }

    /// Refused before any deposit unless every other recipient escrows its key.
    fn check_escrowed(&self, ctx: &Context, sender: &ShieldedKeypair) -> Result<()> {
        let recipients: Vec<ShieldedAddress> = (self.to_others(&sender.signing_pubkey())?)
            .into_iter()
            .map(|payment| *payment.to)
            .collect();
        let check = EscrowedRecipients {
            ring: ctx.ring,
            recipients: &recipients,
        };
        records::patiently("the escrowed keys of the recipients", || {
            ctx.block(check.check(ctx.chain()))
        })
    }

    fn select_held(
        &self,
        scanned: &SpendableDecryptionResult,
        ring: Address,
    ) -> Result<Vec<WalletUtxo>> {
        let total = self.total()?;
        let held = |kind: Spendable| -> Vec<WalletUtxo> {
            scanned
                .utxos()
                .filter(|utxo| {
                    utxo.utxo.asset.asset == self.mint
                        && kind.admits(utxo, ring)
                        && carries_no_data(utxo)
                })
                .cloned()
                .collect()
        };
        let select = |utxos: &[WalletUtxo], widest: usize| -> Result<Vec<WalletUtxo>> {
            Ok(select_spend_where(utxos, self.mint, total, widest, |_| {
                true
            })?)
        };
        let entry = match &self.payees {
            Payees::Confidential(_) => {
                return select(&held(Spendable::WithDefaultRing), MAX_SPEND_INPUTS)
            }
            Payees::Anonymous { entry, .. } => *entry,
        };
        let ring_utxos = held(Spendable::RingOnly);
        let (kind, utxos) = if held_total(&ring_utxos)? >= total {
            (Spendable::RingOnly, ring_utxos)
        } else {
            let default_utxos = held(Spendable::DefaultRingOnly);
            ensure!(
                held_total(&default_utxos)? >= total,
                "neither the sender's ring notes nor the default-ring notes alone fund the payment"
            );
            match entry {
                EntrySpend::Allow => (Spendable::DefaultRingOnly, default_utxos),
                EntrySpend::Refuse => bail!(
                    "the sender's ring notes do not fund the payment, `--entry-spend allow` spends the default-ring notes and publishes the hidden owner's key"
                ),
            }
        };
        if self.sdk_selects() {
            return Ok(utxos);
        }
        let outputs = self.anonymous_outputs();
        let widest = kind
            .widest_anonymous(outputs)
            .with_context(|| format!("no anonymous audit key carries {outputs} outputs"))?;
        select(&utxos, widest)
    }

    /// Refuses up front what the spend would refuse or ignore after the paid steps.
    fn fits(&self, inputs: &Inputs) -> Result<()> {
        match inputs {
            Inputs::Deposits { amounts, .. } => {
                let held = amounts
                    .iter()
                    .fold(0, |sum: u64, amount| sum.saturating_add(*amount));
                self.shape(amounts.len(), held)?;
                if let Payees::Anonymous { entry, .. } = self.payees {
                    match entry {
                        EntrySpend::Refuse => {}
                        EntrySpend::Allow => bail!(
                            "`--entry-spend allow` spends held default-ring notes, `--funding deposit` spends fresh deposits"
                        ),
                    }
                    let outputs = self.anonymous_outputs();
                    ensure!(
                        Spendable::RingOnly
                            .widest_anonymous(outputs)
                            .is_some_and(|widest| widest >= amounts.len()),
                        "no anonymous audit key spends {} deposited notes into {outputs} outputs",
                        amounts.len()
                    );
                }
            }
            Inputs::Held(utxos) => {
                self.shape(utxos.len(), held_total(utxos)?)?;
            }
        }
        Ok(())
    }

    /// The shape `--outputs` names, refused when it cannot carry the payments and the change.
    fn shape(&self, inputs: usize, held: u64) -> Result<Option<Shape>> {
        let slots = self.each().len() + usize::from(held > self.total()?);
        Ok(self
            .outputs
            .map(|outputs| canonical_shape(inputs, outputs.max(slots)))
            .transpose()?)
    }

    fn anonymous_outputs(&self) -> usize {
        self.outputs.unwrap_or(0).max(self.each().len() + 1)
    }

    /// The SDK sizes an anonymous move itself, an exit or an output floor needs the cli's own pick.
    fn sdk_selects(&self) -> bool {
        match &self.payees {
            Payees::Anonymous { default_ring, .. } => {
                default_ring.is_empty() && self.outputs.is_none()
            }
            Payees::Confidential(_) => false,
        }
    }
}

fn sum(payments: &[Payment<&ShieldedAddress>]) -> Result<u64> {
    payments
        .iter()
        .try_fold(0u64, |total, payment| total.checked_add(payment.amount))
        .context("the payments overflow a u64")
}

impl Outflow {
    /// Under the pinned policy's limits, an audit-only ring pins none.
    fn demand(self, ctx: &Context) -> Result<Demand> {
        let policy = ctx.block(ctx.ring.pinned_policy(ctx.chain()))?;
        let limits = policy
            .as_ref()
            .map_or(&[][..], |policy| policy.table.limits());
        self.demand_under(limits)
    }

    /// Refused past a nonzero cap before anything is deposited, approval past a nonzero bound.
    fn demand_under(self, limits: &[OutflowLimit]) -> Result<Demand> {
        let asset = *Member::asset(&self.mint)?.as_bytes();
        let over = |bound: u64| bound != 0 && self.amount > bound;
        let mut approval = false;
        for limit in limits.iter().filter(|limit| limit.asset == asset) {
            ensure!(
                !over(limit.cap),
                "the outflow {} passes the policy cap {} of mint {}",
                self.amount,
                limit.cap,
                self.mint
            );
            approval |= over(limit.cosign_above);
        }
        Ok(if approval {
            Demand::Approval
        } else {
            Demand::Transfer
        })
    }
}

impl CoSigner {
    pub(crate) fn read(ctx: &Context, arg: &CosignerArg) -> Result<Self> {
        let keypair = arg
            .cosigner_keypair
            .as_deref()
            .map(|path| file::read_keypair(&ctx.path(path)))
            .transpose()?;
        Ok(Self { keypair })
    }

    pub(crate) fn sign(
        &self,
        config: &CustomRingConfig,
        demand: Demand,
    ) -> Result<Option<&(dyn Signer + Sync)>> {
        self.sign_for(Requirement::of(config.account(), demand)?)
    }

    /// Refused when the operation demands a co-signer the operator did not pass, or another key is passed.
    fn sign_for(&self, requirement: Requirement) -> Result<Option<&(dyn Signer + Sync)>> {
        let provided = self.keypair.as_ref().map(Signer::pubkey);
        if let (Some(configured), Some(found)) = (requirement.configured, provided) {
            ensure!(
                found == configured,
                "the configured co-signer is {configured}, not {found}"
            );
        }
        ensure!(
            requirement.demanded.is_none() || provided.is_some(),
            "the operation needs the co-signer's approval, pass --cosigner-keypair"
        );
        Ok(self
            .keypair
            .as_ref()
            .filter(|_| requirement.demanded.is_some())
            .map(|keypair| keypair as &(dyn Signer + Sync)))
    }
}

impl Requirement {
    fn of(config: &RingProgramConfig, demand: Demand) -> Result<Self> {
        let demanded = CoSignDemand {
            approval_required: demand == Demand::Approval,
            classes: demand.classes(),
            withdrawals: Vec::new(),
        };
        Ok(Self {
            configured: config.co_signer().copied(),
            demanded: demanded.signer(config)?,
        })
    }
}

impl Demand {
    const fn classes(self) -> CoSignScope {
        match self {
            Self::Deposit => CoSignScope::DEPOSITS,
            Self::Transfer | Self::Approval => CoSignScope::TRANSFERS,
        }
    }
}

impl AllowEnrolment<'_> {
    /// A curated `Allow` list is the curator's to write.
    fn send(self, ctx: &Context) -> Result<()> {
        let Some(pinned) = policy::pinned_if_any(ctx)? else {
            return Ok(());
        };
        if !pinned.policy.table.referenced().contains(ListId::Allow) {
            return Ok(());
        }
        if let Some(ListRegistry::Curator(registry)) = pinned.registry.registry_for(ListId::Allow) {
            line("allow", format_args!("curated by {registry}"));
            return Ok(());
        }
        let subjects = self
            .parties
            .iter()
            .map(|(party, keys)| {
                Ok(Subject {
                    member: Member::owner_tag(keys.pubkey().as_array())?,
                    label: (*party).to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let outcomes = ListUpdate {
            authority: self.authority,
            list_id: ListId::Allow,
            subjects: &subjects,
            change: ListChange::Set,
        }
        .send(ctx)?;
        for (subject, outcome) in subjects.iter().zip(outcomes) {
            line("allow", format_args!("{} {outcome}", subject.label));
        }
        Ok(())
    }
}

impl Deposit<'_> {
    fn send(self, ctx: &Context) -> Result<RingDepositReceipt> {
        let state = match self.config.mode {
            RingMode::Anonymous => Some(ctx.anonymous_ring_store(self.sender, self.config).load()?),
            RingMode::Off | RingMode::Registry => None,
        };
        let recipient = match &state {
            Some(state) => DepositRecipient::Anonymous {
                keys: self.sender,
                state,
            },
            None => DepositRecipient::Confidential(self.sender.shielded_address()?),
        };
        let deposit = RingDeposit {
            ring: ctx.ring,
            payer: self.payer,
            recipient,
            tree: pda::tree(0),
            asset: self.asset,
            amount: self.amount,
            cosigner: self.cosigner,
        };
        Ok(ctx.block(deposit.send(ctx.chain()))?)
    }
}

impl Inputs<'_> {
    fn drawn_lamports(&self) -> u64 {
        match self {
            Self::Deposits { asset, amounts, .. } => amounts.iter().fold(0, |sum, amount| {
                sum.saturating_add(deposit_lamports(*asset, *amount))
            }),
            Self::Held(_) => 0,
        }
    }
}

impl Transfer<'_> {
    fn held_utxos(&self, ctx: &Context) -> Result<Vec<WalletUtxo>> {
        self.payments
            .select_held(&self.scan(ctx)?, ctx.ring.program_id())
    }

    /// Runs after the enrolments, their top-ups would otherwise leave the deposits short.
    fn fund(&self, ctx: &Context, drawn: u64) -> Result<()> {
        let fees = SENDER_FEE_BUDGET + PAYER_FEE_BUDGET;
        ctx.fund(self.payer.pubkey(), drawn.saturating_add(fees))
    }

    fn send(self, ctx: &Context, inputs: Inputs) -> Result<Sent> {
        let mut deposits = Vec::new();
        let mut fund_and_spend = |inputs: Inputs| -> Result<Signature> {
            let utxos = match inputs {
                Inputs::Held(utxos) => utxos,
                Inputs::Deposits {
                    asset,
                    amounts,
                    cosigner,
                } => {
                    let mut deposit = |amount| -> Result<RingDepositReceipt> {
                        let receipt = Deposit {
                            payer: self.payer,
                            sender: self.sender,
                            config: self.config,
                            asset,
                            amount,
                            cosigner,
                        }
                        .send(ctx)?;
                        deposits.push(receipt.signature);
                        Ok(receipt)
                    };
                    let [first, second] = amounts;
                    let receipts = [deposit(first)?, deposit(second)?];
                    // Photon learns a tree from its first indexed transaction.
                    let [_, last] = &receipts;
                    ctx.wait_for_indexed(last.signature)?;
                    self.deposited_utxos(ctx, &receipts)?
                }
            };
            self.spend(ctx, utxos)
        };
        let transact =
            fund_and_spend(inputs).map_err(|error| name_kept_deposits(error, &deposits))?;
        Ok(Sent { deposits, transact })
    }

    /// The deposited notes as the sender's own scan reads them, leaf and nullifier included.
    fn deposited_utxos(
        &self,
        ctx: &Context,
        receipts: &[RingDepositReceipt],
    ) -> Result<Vec<WalletUtxo>> {
        let scanned = self.scan(ctx)?;
        let utxos: Vec<WalletUtxo> = receipts
            .iter()
            .filter_map(|receipt| {
                // The random blinding names the note, the scan adds the deposit's empty ring data.
                scanned
                    .utxos()
                    .find(|held| held.utxo.blinding == receipt.utxo.blinding)
            })
            .cloned()
            .collect();
        ensure!(
            utxos.len() == receipts.len(),
            "the indexer returned {} of the {} deposited notes",
            utxos.len(),
            receipts.len()
        );
        Ok(utxos)
    }

    fn scan(&self, ctx: &Context) -> Result<SpendableDecryptionResult> {
        WalletScan {
            keys: self.sender,
            registry: self.registry,
            config: self.config,
        }
        .fetch(ctx)
    }

    fn spend(&self, ctx: &Context, inputs: Vec<WalletUtxo>) -> Result<Signature> {
        let shape = self.payments.shape(inputs.len(), held_total(&inputs)?)?;
        let tree_id = inputs
            .first()
            .context("no note funds the transfer")?
            .tree_id;
        let ring = ctx.ring.program_id();
        let transaction = |inputs, fee_payer| -> Result<ConfidentialTransaction> {
            Ok(
                ConfidentialTransaction::new_with_ring(inputs, fee_payer, ring)?
                    .with_output_tree_id(tree_id)?,
            )
        };
        match &self.payments.payees {
            Payees::Confidential(payees) => {
                let mut transaction = transaction(inputs, self.sender.pubkey())?;
                for payment in payees {
                    if self.payments.mint == SOL_MINT {
                        transaction.transfer_sol(&payment.to, payment.amount)?;
                    } else {
                        transaction.transfer(&payment.to, self.payments.mint, payment.amount)?;
                    }
                }
                if let Some(shape) = shape {
                    transaction.pad_utxos(shape, &self.sender.shielded_address()?)?;
                }
                let transfer = CustomRingTransfer::new(CustomRingTransferInput {
                    ring: ctx.ring,
                    sender: self.sender,
                    nullifier_key: Some(&self.sender.nullifier_key),
                    transaction,
                });
                // The owner signs its spends, it pays the transaction too.
                TopUp {
                    funder: self.payer,
                    who: self.sender.pubkey(),
                    lamports: SENDER_FEE_BUDGET,
                }
                .send(ctx)?;
                ctx.submit(transfer, self.sender, self.cosigner.as_slice())
            }
            Payees::Anonymous {
                ring: payees,
                default_ring,
                entry,
            } => {
                let store = ctx.anonymous_ring_store(self.sender, self.config);
                let state = store.load()?;
                let mint = self.registry.mint(&self.payments.mint)?;
                // The hidden owner never signs in public, the payer funds its spend.
                let transfer = match self.payments.sdk_selects() {
                    true => {
                        let select = AnonymousMove {
                            ring: ctx.ring,
                            sender: self.sender,
                            nullifier_key: &self.sender.nullifier_key,
                            signer: &self.sender.signing_key,
                            state: &state,
                            payer: self.payer.pubkey(),
                            utxos: &inputs,
                            asset: mint,
                            payments: payees
                                .iter()
                                .map(|payment| RingPayment {
                                    to: payment.to.clone(),
                                    amount: payment.amount,
                                })
                                .collect(),
                            entry: *entry,
                        };
                        ctx.block(select.select(ctx.chain()))?
                    }
                    false => {
                        let mut transaction = transaction(inputs, self.payer.pubkey())?;
                        for payment in default_ring {
                            transaction.transfer_with_ring(
                                &payment.to,
                                mint,
                                payment.amount,
                                None,
                            )?;
                        }
                        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
                            ring: ctx.ring,
                            sender: self.sender,
                            nullifier_key: Some(&self.sender.nullifier_key),
                            transaction,
                        })
                        .with_anonymous_signer(&self.sender.signing_key, &state);
                        for payment in payees {
                            transfer = transfer.with_payment(AnonymousPayment {
                                to: payment.to.clone(),
                                asset: mint,
                                amount: payment.amount,
                            })?;
                        }
                        match shape {
                            Some(shape) => transfer.with_shape(shape)?,
                            None => transfer,
                        }
                    }
                };
                let landed = ctx.land(transfer, self.payer, self.cosigner.as_slice())?;
                let signature = landed.signature;
                let recorded = FirstContacts {
                    store: &store,
                    signature,
                    pending: &landed.first_contacts,
                }
                .record(ctx);
                if let Err(error) = recorded {
                    ui::warn(format!(
                        "payment {signature} landed, its first contacts stay unrecorded, {error:#}"
                    ));
                }
                Ok(signature)
            }
        }
    }
}

impl Spendable {
    fn admits(self, utxo: &WalletUtxo, ring: Address) -> bool {
        let in_ring = utxo.utxo.ring_program_id == Some(ring);
        match self {
            Self::RingOnly => in_ring,
            Self::WithDefaultRing => in_ring || utxo.is_default_ring_spendable(),
            Self::DefaultRingOnly => utxo.is_default_ring_spendable(),
        }
    }

    /// The most inputs an anonymous key serves with room for `outputs`.
    fn widest_anonymous(self, outputs: usize) -> Option<usize> {
        let keyed = |shape: Shape| match self {
            Self::RingOnly => shape_keyed(RingRail::Anonymous, shape),
            Self::DefaultRingOnly => AnonymousSpend {
                inputs: shape.n_inputs(),
                outputs: shape.n_outputs(),
                spends_default_ring: true,
            }
            .audit_key()
            .is_some(),
            Self::WithDefaultRing => false,
        };
        // Ordinary padding publishes every input of the SPP shape, the shape itself must carry a key.
        SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape.n_outputs() >= outputs && keyed(*shape))
            .map(|shape| shape.n_inputs())
            .max()
    }
}

impl FirstContacts<'_> {
    /// The leaves come from the confirmed transaction over RPC, the indexer never learns the signature.
    fn record(self, ctx: &Context) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let groups = ctx
            .rpc()
            .fetch_confirmed_instruction_groups(&self.signature)?;
        let events = indexed_events_from_instruction_groups(
            Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            &groups.groups,
        );
        let leaf = |utxo_hash: &[u8; 32]| {
            events
                .iter()
                .filter_map(|event| event.decoded.as_ref().ok())
                .find_map(|event| {
                    let position = event
                        .outputs
                        .iter()
                        .position(|output| output.utxo_hash == *utxo_hash)?;
                    event
                        .first_output_leaf_index
                        .checked_add(u64::try_from(position).ok()?)
                })
        };
        let confirmed = self
            .pending
            .iter()
            .map(|contact| {
                leaf(&contact.utxo_hash)
                    .map(|leaf_index| contact.confirm(leaf_index))
                    .context("the confirmed transaction holds no leaf of a first contact")
            })
            .collect::<Result<Vec<_>>>()?;
        self.store.update(|state| {
            for contact in confirmed {
                state.record_first_contact(contact);
            }
            Ok(())
        })
    }
}

/// A rerun deposits again, the error names what the sender already holds.
fn name_kept_deposits(error: anyhow::Error, deposits: &[Signature]) -> anyhow::Error {
    if deposits.is_empty() {
        return error;
    }
    let noun = match deposits.len() {
        1 => "deposit",
        _ => "deposits",
    };
    let landed: Vec<String> = deposits.iter().map(Signature::to_string).collect();
    error.context(format!(
        "the {noun} {} landed in the sender's ring balance, `transfer --funding held` spends from that balance",
        landed.join(" and ")
    ))
}

fn deposit_lamports(asset: DepositAsset, amount: u64) -> u64 {
    match asset {
        DepositAsset::Sol => amount,
        DepositAsset::Spl(_) => 0,
    }
}

fn held_total(utxos: &[WalletUtxo]) -> Result<u64> {
    utxos
        .iter()
        .try_fold(0u64, |held, utxo| held.checked_add(utxo.utxo.amount))
        .context("the inputs overflow a u64")
}

fn granted(ctx: &Context, reader: &ReaderKey) -> Result<bool> {
    let record = ctx.block(ctx.ring.access_record(ctx.chain(), reader))?;
    Ok(record.is_some())
}

/// The `list` member argument of a party.
fn owner_tag(address: &ShieldedAddress) -> Result<Address> {
    Ok(Address::new_from_array(address.confidential_view_tag()?))
}

fn print_signatures(ctx: &Context, sent: &Sent) -> Result<()> {
    for signature in &sent.deposits {
        line("deposit", signature);
    }
    line("transact", sent.transact);
    let meta = ctx
        .rpc()
        .fetch_confirmed_transaction(&sent.transact)?
        .transaction
        .meta;
    let logs: Option<Vec<String>> = meta.and_then(|meta| meta.log_messages.into());
    for log in logs.iter().flatten() {
        if let Some(log) = log.strip_prefix("Program log: ") {
            println!("  log       {log}");
        }
    }
    Ok(())
}

/// What the auditor opens for a granted reader, once the indexer has the slot.
fn read_back(ctx: &Context, reader: &Keypair, signature: Signature) -> Result<()> {
    println!("waiting for the indexer and the ring rpc to open the transaction");
    ctx.wait_for_indexed(signature)?;
    let ring_rpc = ctx.ring_rpc();
    let service = ring_rpc.service_pubkey()?;
    if let Trust::Pinned(pinned) = ctx.trust(Trust::Unpinned)? {
        ensure!(
            pinned == service,
            "the ring rpc reports service key {service}, ring.toml pins {pinned}"
        );
    }
    let target = ReadTarget {
        cluster: ctx.rpc().genesis_hash()?,
        service,
        ring: ctx.ring.program_id(),
    };
    let opened = ring_rpc
        // The submission carries one ring operation, its SPP event sits at index zero.
        .wait_for_decrypted(target, reader, signature, 0)
        .context("the ring rpc did not open the transfer")?;
    let heading = format!("auditor sees slot {} at {signature}", opened.slot);
    ui::heading(icon::AUDITOR, &heading);
    if let Some(sender) = &opened.sender {
        println!("  hidden sender {}", sender.owner_key.0);
    }
    println!("  nullifiers {}", opened.nullifiers.len());
    for output in &opened.outputs {
        let kind = match output.kind {
            DecryptedOutputKind::Ring => "ring",
            DecryptedOutputKind::Exit => "exit",
            DecryptedOutputKind::Dummy => "dummy",
        };
        let Some(utxo) = &output.utxo else {
            println!("  slot {}  {kind}", output.slot_index);
            continue;
        };
        let opened = OpenedSlot {
            slot: output.slot_index,
            kind,
            owner: utxo.owner_key.0,
            asset: utxo
                .mint
                .map_or_else(|| hex::encode(utxo.asset.0), |mint| mint.0.to_string()),
            amount: utxo.amount,
        };
        println!("{opened}");
    }
    for error in &opened.payload_errors {
        println!("  slot {} payload {:?}", error.slot_index, error.kind);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;
    use zolana_keypair::SigningKey;

    use super::*;
    use crate::tests::transfer_args;

    const RING: Address = Address::new_from_array([4; 32]);

    fn configured(co_signer: Address, scope: CoSignScope) -> RingProgramConfig {
        let mut config = RingProgramConfig::zeroed();
        config.co_signer = co_signer;
        config.co_sign_scope = scope.bits();
        config
    }

    fn refusal<T: std::fmt::Debug>(result: Result<T>) -> String {
        result.expect_err("refused").to_string()
    }

    const ABSENT: CoSigner = CoSigner { keypair: None };

    impl CoSigner {
        fn passing(keypair: &Keypair) -> Self {
            Self {
                keypair: Some(keypair.insecure_clone()),
            }
        }

        fn signs(&self, config: &RingProgramConfig, demand: Demand) -> Result<Option<Address>> {
            Ok(self
                .sign_for(Requirement::of(config, demand)?)?
                .map(|cosigner| cosigner.pubkey()))
        }
    }

    #[test]
    fn blanket_scope_and_private_approval_require_the_configured_signer() {
        let (key, stranger) = (Keypair::new(), Keypair::new());
        let transfers = configured(key.pubkey(), CoSignScope::TRANSFERS);
        assert!(
            refusal(ABSENT.signs(&transfers, Demand::Transfer)).contains("pass --cosigner-keypair")
        );
        assert_eq!(
            CoSigner::passing(&key)
                .signs(&transfers, Demand::Transfer)
                .unwrap(),
            Some(key.pubkey())
        );
        assert!(
            refusal(CoSigner::passing(&stranger).signs(&transfers, Demand::Transfer))
                .starts_with("the configured co-signer is")
        );
        let withdrawals = configured(key.pubkey(), CoSignScope::WITHDRAWALS);
        assert_eq!(ABSENT.signs(&withdrawals, Demand::Transfer).unwrap(), None);
        assert!(refusal(ABSENT.signs(&withdrawals, Demand::Approval))
            .contains("pass --cosigner-keypair"));
        let none = RingProgramConfig::zeroed();
        assert_eq!(ABSENT.signs(&none, Demand::Transfer).unwrap(), None);
        assert!(refusal(ABSENT.signs(&none, Demand::Approval))
            .contains("dual control needs a configured co-signer"));
    }

    #[test]
    fn deposits_and_transfers_hand_the_co_signer_only_to_the_class_it_gates() {
        let key = Keypair::new();
        let passed = CoSigner::passing(&key);
        for (scope, deposit, transfer) in [
            (CoSignScope::DEPOSITS, true, false),
            (CoSignScope::TRANSFERS, false, true),
            (CoSignScope::WITHDRAWALS, false, false),
        ] {
            let config = configured(key.pubkey(), scope);
            let handed = |demand| passed.signs(&config, demand).unwrap().is_some();
            assert_eq!(handed(Demand::Deposit), deposit, "{scope:?}");
            assert_eq!(handed(Demand::Transfer), transfer, "{scope:?}");
        }
    }

    fn limits(cap: u64, cosign_above: u64) -> [OutflowLimit; 1] {
        [OutflowLimit {
            asset: *Member::asset(&SOL_MINT).unwrap().as_bytes(),
            cap,
            cosign_above,
        }]
    }

    fn sol(amount: u64) -> Outflow {
        Outflow {
            mint: SOL_MINT,
            amount,
        }
    }

    #[test]
    fn a_different_owner_charges_the_payment_and_uses_a_strict_nonzero_threshold() {
        for (threshold, amount, demand) in [
            (10, 10, Demand::Transfer),
            (10, 11, Demand::Approval),
            (0, u64::MAX, Demand::Transfer),
        ] {
            let demanded = sol(amount).demand_under(&limits(0, threshold)).unwrap();
            assert_eq!(demanded, demand);
        }
        assert_eq!(sol(u64::MAX).demand_under(&[]).unwrap(), Demand::Transfer);
        let other = Outflow {
            mint: Address::new_from_array([7; 32]),
            amount: 5,
        };
        assert_eq!(
            other.demand_under(&limits(0, 1)).unwrap(),
            Demand::Transfer,
            "another mint"
        );
    }

    #[test]
    fn a_failed_transfer_names_the_deposits_it_landed() {
        let landed = [Signature::from([1; 64]), Signature::from([2; 64])];
        let failed = name_kept_deposits(anyhow::anyhow!("the prover is down"), &landed);
        let text = format!("{failed:#}");
        assert!(text.contains("--funding held"), "{text}");
        for signature in landed {
            assert!(text.contains(&signature.to_string()), "{text}");
        }
        assert!(text.ends_with("the prover is down"), "{text}");
        let [first, _] = landed;
        let one = name_kept_deposits(anyhow::anyhow!("the prover is down"), &[first]);
        let text = format!("{one:#}");
        assert!(
            text.starts_with(&format!("the deposit {first} landed")),
            "{text}"
        );
        let before_any = name_kept_deposits(anyhow::anyhow!("the prover is down"), &[]);
        assert_eq!(format!("{before_any:#}"), "the prover is down");
    }

    #[test]
    fn the_payer_is_funded_with_the_sol_it_deposits() {
        let deposits = |asset| Inputs::Deposits {
            asset,
            amounts: [3, 4],
            cosigner: None,
        };
        assert_eq!(deposits(DepositAsset::Sol).drawn_lamports(), 7);
        let spl = DepositAsset::Spl(custom_ring_sdk::DepositSplAccounts {
            mint: RING,
            user_token: RING,
            token_program: RING,
        });
        assert_eq!(deposits(spl).drawn_lamports(), 0);
        assert_eq!(Inputs::Held(Vec::new()).drawn_lamports(), 0);
    }

    #[test]
    fn an_outflow_past_the_cap_is_refused() {
        assert!(sol(10).demand_under(&limits(10, 0)).is_ok());
        assert!(refusal(sol(11).demand_under(&limits(10, 0))).contains("passes the policy cap 10"));
    }

    fn keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    fn request(seed: u8, ring: Address) -> Recipient {
        let address = address::ring_address(&keypair(seed), ring, 0).unwrap();
        Recipient::Ring(Box::new(RingPaymentRequest::new(address)))
    }

    #[test]
    fn each_recipient_must_fit_the_rings_mode() {
        let shielded = Recipient::Shielded(keypair(1).shielded_address().unwrap());
        let ring = request(2, RING);
        for mode in [RingMode::Off, RingMode::Registry] {
            assert!(PaymentPlan::new(std::slice::from_ref(&shielded))
                .resolve(mode, RING)
                .is_ok());
            let refused = PaymentPlan::new(&[shielded.clone(), ring.clone()]).resolve(mode, RING);
            assert!(refusal(refused).contains("pays an anonymous ring"));
        }
        let anonymous = PaymentPlan::new(std::slice::from_ref(&ring))
            .resolve(RingMode::Anonymous, RING)
            .unwrap();
        assert!(matches!(
            anonymous.payees,
            Payees::Anonymous { ref ring, ref default_ring, entry: EntrySpend::Refuse }
                if ring.len() == 1 && default_ring.is_empty()
        ));
        let refused =
            PaymentPlan::new(std::slice::from_ref(&shielded)).resolve(RingMode::Anonymous, RING);
        assert!(refusal(refused).contains("not shielded address"));
        let exit = PaymentPlan::new(&[shielded.clone(), ring.clone()])
            .with_default_ring()
            .resolve(RingMode::Anonymous, RING)
            .unwrap();
        assert!(matches!(
            exit.payees,
            Payees::Anonymous { ref ring, ref default_ring, .. }
                if ring.len() == 1 && default_ring.len() == 1
        ));
        let allowed = PaymentPlan::new(std::slice::from_ref(&ring))
            .with_entry_spend(EntrySpend::Allow)
            .resolve(RingMode::Anonymous, RING)
            .unwrap();
        assert!(matches!(
            allowed.payees,
            Payees::Anonymous {
                entry: EntrySpend::Allow,
                ..
            }
        ));
        let confidential = PaymentPlan::new(std::slice::from_ref(&shielded))
            .with_entry_spend(EntrySpend::Allow)
            .resolve(RingMode::Off, RING);
        assert!(refusal(confidential).contains("`--entry-spend` gates"));
        let confidential = PaymentPlan::new(&[shielded])
            .with_default_ring()
            .resolve(RingMode::Off, RING);
        assert!(refusal(confidential).contains("pays out of an anonymous ring"));
        let foreign = [request(2, Address::new_from_array([5; 32]))];
        let refused = PaymentPlan::new(&foreign).resolve(RingMode::Anonymous, RING);
        assert!(refusal(refused).contains("pays ring"));
    }

    #[test]
    fn a_flag_that_differs_from_a_requests_amount_or_mint_is_refused() {
        let mint = Address::new_from_array([7; 32]);
        let mut asked =
            RingPaymentRequest::new(address::ring_address(&keypair(2), RING, 0).unwrap());
        asked.amount = Some(5);
        asked.mint = Some(mint);
        let recipients = [Recipient::Ring(Box::new(asked)), request(3, RING)];
        let plan = || PaymentPlan::new(&recipients);
        let resolve = |plan: PaymentPlan<'_>| plan.resolve(RingMode::Anonymous, RING);
        let resolved = resolve(plan()).unwrap();
        assert_eq!(resolved.mint, mint);
        let amounts: Vec<u64> = resolved
            .each()
            .iter()
            .map(|payment| payment.amount)
            .collect();
        assert_eq!(amounts, [5, DEFAULT_TRANSACT_AMOUNT]);
        assert!(refusal(resolve(plan().with_amount(6))).contains("--amount names 6"));
        assert!(refusal(resolve(plan().with_mint(SOL_MINT))).contains("asks for mint"));
        let zero = PaymentPlan::new(&recipients[1..]).with_amount(0);
        assert!(refusal(resolve(zero)).contains("nonzero amount"));
    }

    #[test]
    fn the_transfer_flags_reach_the_plan() {
        let Recipient::Ring(request) = request(2, RING) else {
            panic!("a ring request");
        };
        let request = request.to_string();
        let shielded = keypair(1).shielded_address().unwrap().to_string();
        let mint = Address::new_from_array([7; 32]);
        let mint_arg = mint.to_string();
        let resolve = |flags: &[&str]| {
            let argv: Vec<&str> = [
                request.as_str(),
                "--amount",
                "5",
                "--mint",
                mint_arg.as_str(),
                "--outputs",
                "4",
            ]
            .into_iter()
            .chain(flags.iter().copied())
            .collect();
            PaymentPlan::of(&transfer_args(&argv).unwrap()).resolve(RingMode::Anonymous, RING)
        };
        assert!(refusal(resolve(&[shielded.as_str()])).contains("not shielded address"));
        let payments = resolve(&[shielded.as_str(), "--default-ring"]).unwrap();
        assert_eq!(payments.mint, mint);
        assert_eq!(payments.outputs, Some(4));
        assert!(payments.each().iter().all(|payment| payment.amount == 5));
        assert!(matches!(
            payments.payees,
            Payees::Anonymous { ref default_ring, entry: EntrySpend::Refuse, .. }
                if default_ring.len() == 1
        ));
        let allowed = resolve(&["--funding", "held", "--entry-spend", "allow"]).unwrap();
        assert!(matches!(
            allowed.payees,
            Payees::Anonymous {
                entry: EntrySpend::Allow,
                ..
            }
        ));
    }

    #[test]
    fn a_payment_to_the_senders_own_key_charges_no_outflow() {
        let sender = keypair(1);
        let mut own = sender.shielded_address().unwrap();
        own.viewing_pubkey = zolana_keypair::ViewingKey::new().pubkey();
        let other = keypair(2).shielded_address().unwrap();
        let payments = Payments {
            mint: SOL_MINT,
            payees: Payees::Confidential(vec![
                Payment { to: own, amount: 4 },
                Payment {
                    to: other,
                    amount: 6,
                },
            ]),
            outputs: None,
        };
        assert_eq!(payments.outflow(&sender.signing_pubkey()).unwrap(), sol(6));
        assert_eq!(payments.total().unwrap(), 10);
    }

    #[test]
    fn a_payment_set_no_keyed_shape_carries_is_refused() {
        let deposits = Inputs::Deposits {
            asset: DepositAsset::Sol,
            amounts: [3, 3],
            cosigner: None,
        };
        let to = keypair(1).shielded_address().unwrap();
        let confidential = |outputs| Payments {
            mint: SOL_MINT,
            payees: Payees::Confidential(vec![Payment { to, amount: 6 }]),
            outputs,
        };
        assert!(confidential(None).fits(&deposits).is_ok());
        assert!(confidential(Some(4)).fits(&deposits).is_ok());
        assert!(confidential(Some(17)).fits(&deposits).is_err());
        let to = address::ring_address(&keypair(2), RING, 0).unwrap();
        let anonymous = |count| Payments {
            mint: SOL_MINT,
            payees: Payees::Anonymous {
                ring: vec![
                    Payment {
                        to: to.clone(),
                        amount: 1
                    };
                    count
                ],
                default_ring: Vec::new(),
                entry: EntrySpend::Refuse,
            },
            outputs: None,
        };
        assert!(anonymous(7).fits(&deposits).is_ok());
        let refused = refusal(anonymous(8).fits(&deposits));
        assert!(refused.contains("no anonymous audit key"), "{refused}");
    }

    fn held_utxo(ring: Option<Address>, amount: u64) -> WalletUtxo {
        let mut held = WalletUtxo::dummy_with_blinding([amount as u8; 32], 0).unwrap();
        held.utxo.amount = amount;
        held.utxo.ring_program_id = ring;
        held
    }

    fn scanned(utxos: Vec<WalletUtxo>) -> SpendableDecryptionResult {
        SpendableDecryptionResult {
            utxos_with_data: utxos,
            ..Default::default()
        }
    }

    fn rings(picked: Result<Vec<WalletUtxo>>) -> Vec<Option<Address>> {
        picked
            .unwrap()
            .iter()
            .map(|utxo| utxo.utxo.ring_program_id)
            .collect()
    }

    struct AnonymousPlan {
        entry: EntrySpend,
        outputs: Option<usize>,
        amount: u64,
    }

    impl AnonymousPlan {
        fn payments(self) -> Payments {
            Payments {
                mint: SOL_MINT,
                payees: Payees::Anonymous {
                    ring: vec![Payment {
                        to: address::ring_address(&keypair(2), RING, 0).unwrap(),
                        amount: self.amount,
                    }],
                    default_ring: Vec::new(),
                    entry: self.entry,
                },
                outputs: self.outputs,
            }
        }
    }

    #[test]
    fn an_anonymous_ring_spends_default_ring_notes_only_on_an_explicit_allow() {
        let ring = |amount| held_utxo(Some(RING), amount);
        let default = |amount| held_utxo(None, amount);
        let mut other_mint = ring(30);
        other_mint.utxo.asset = zolana_transaction::Mint::new(Address::new_from_array([7; 32]), 7);
        let mut with_data = ring(30);
        with_data.data_hash = Some([1; 32]);
        let ring_short = scanned(vec![ring(3), default(7), other_mint, with_data]);
        let both_short = scanned(vec![ring(3), default(4)]);
        let ring_covers = scanned(vec![ring(3), ring(4), default(7)]);
        for outputs in [None, Some(4)] {
            let select = |entry, scanned| {
                AnonymousPlan {
                    entry,
                    outputs,
                    amount: 6,
                }
                .payments()
                .select_held(scanned, RING)
            };
            let refused = refusal(select(EntrySpend::Refuse, &ring_short));
            assert!(refused.contains("`--entry-spend allow`"), "{refused}");
            for entry in [EntrySpend::Refuse, EntrySpend::Allow] {
                let refused = refusal(select(entry, &both_short));
                assert!(refused.contains("alone"), "{refused}");
            }
            assert_eq!(rings(select(EntrySpend::Allow, &ring_short)), [None]);
            assert_eq!(
                rings(select(EntrySpend::Allow, &ring_covers)),
                [Some(RING); 2]
            );
        }
        let plan = |outputs, amount| AnonymousPlan {
            entry: EntrySpend::Allow,
            outputs,
            amount,
        };
        let ring_wide = scanned(vec![ring(3), ring(4), ring(5)]);
        let picked = |outputs| rings(plan(outputs, 6).payments().select_held(&ring_wide, RING));
        assert_eq!(picked(None).len(), 3, "the SDK picks from the whole pool");
        assert_eq!(picked(Some(4)).len(), 2);
        let merge = scanned((0..20).map(|_| ring(1)).chain([default(30)]).collect());
        let refused = refusal(plan(Some(8), 20).payments().select_held(&merge, RING));
        assert!(refused.contains("merge first"), "{refused}");
        let refused = refusal(plan(Some(16), 6).payments().select_held(&ring_short, RING));
        assert!(refused.contains("no anonymous audit key"), "{refused}");
        let entry_wide = scanned((0..9).map(|_| default(1)).collect());
        let refused = refusal(plan(Some(4), 9).payments().select_held(&entry_wide, RING));
        assert!(refused.contains("more than 8"), "{refused}");
        let deposits = Inputs::Deposits {
            asset: DepositAsset::Sol,
            amounts: [3, 3],
            cosigner: None,
        };
        let refused = refusal(plan(None, 6).payments().fits(&deposits));
        assert!(refused.contains("`--funding deposit`"), "{refused}");
    }

    #[test]
    fn a_confidential_ring_spends_ring_and_default_ring_notes_together() {
        let to = keypair(1).shielded_address().unwrap();
        let payments = Payments {
            mint: SOL_MINT,
            payees: Payees::Confidential(vec![Payment { to, amount: 6 }]),
            outputs: None,
        };
        let held = scanned(vec![held_utxo(Some(RING), 3), held_utxo(None, 4)]);
        assert_eq!(rings(payments.select_held(&held, RING)), [None, Some(RING)]);
    }

    #[test]
    fn an_anonymous_held_spend_stays_within_a_keyed_width() {
        assert_eq!(Spendable::RingOnly.widest_anonymous(2), Some(32));
        assert_eq!(Spendable::RingOnly.widest_anonymous(3), Some(24));
        assert_eq!(Spendable::RingOnly.widest_anonymous(8), Some(16));
        assert_eq!(Spendable::RingOnly.widest_anonymous(16), Some(1));
        assert_eq!(Spendable::RingOnly.widest_anonymous(17), None);
        for outputs in [2, 4, 8] {
            assert_eq!(
                Spendable::DefaultRingOnly.widest_anonymous(outputs),
                Some(8)
            );
        }
        assert_eq!(Spendable::WithDefaultRing.widest_anonymous(2), None);
        let in_ring = held_utxo(Some(RING), 1);
        let default = held_utxo(None, 1);
        let foreign = held_utxo(Some(Address::new_from_array([5; 32])), 1);
        for spendable in [Spendable::RingOnly, Spendable::WithDefaultRing] {
            assert!(spendable.admits(&in_ring, RING));
            assert!(!spendable.admits(&foreign, RING));
        }
        assert!(!Spendable::RingOnly.admits(&default, RING));
        assert!(Spendable::WithDefaultRing.admits(&default, RING));
        assert!(Spendable::DefaultRingOnly.admits(&default, RING));
        assert!(!Spendable::DefaultRingOnly.admits(&in_ring, RING));
        let mut ring_data = default.clone();
        ring_data.ring_data_hash = Some([0; 32]);
        assert!(!Spendable::DefaultRingOnly.admits(&ring_data, RING));
    }

    #[test]
    fn a_recipient_parses_as_a_shielded_address_or_a_zolana_request() {
        let address = keypair(1).shielded_address().unwrap();
        assert_eq!(
            address.to_string().parse::<Recipient>(),
            Ok(Recipient::Shielded(address))
        );
        let Recipient::Ring(expected) = request(2, RING) else {
            panic!("a ring request");
        };
        assert_eq!(
            expected.to_string().parse::<Recipient>(),
            Ok(Recipient::Ring(expected.clone()))
        );
        assert!("zolana:not-an-address".parse::<Recipient>().is_err());
        assert!("not-an-address"
            .parse::<Recipient>()
            .unwrap_err()
            .contains("neither a shielded address nor a `zolana:` request"));
    }
}
