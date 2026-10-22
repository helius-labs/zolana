//! The hidden owner signs inside the AnonymousRingEddsa proof.

use async_trait::async_trait;
use custom_ring_interface::{
    stream::{tag_epoch, SlotSecret},
    RingMode, RingRail,
};
use solana_account::Account;
use solana_address::Address;
pub use zolana_client::ANCHOR_DECOYS;
use zolana_client::{
    AnonymousRingState, AsyncIndexer, AsyncRpc, AsyncZolanaClient, ClientError, MerkleProof,
    PairAnchor, PaymentStream, SentFirstContact, Shape, TagAllocation,
};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    error::ShieldedPoolError,
    pda,
    token_account::{AnonymousExitDestination, TokenAccountControl, TokenAccountState},
    tree_slot::tree_id_field,
    SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{Curve, NullifierKey, PublicKey, RingAddress, SigningKey};
use zolana_ring_transaction::{
    AnonymousSlots, RingDelivery, RingOutputRail, StreamPayment, StreamPosition,
};
use zolana_transaction::{
    instructions::transact::{
        ring_spend_message, ConfidentialTransaction, SettlementTransfer, SppProofInputs,
    },
    Mint, ShieldedKeys, WalletUtxo, REDACTED,
};

use super::{
    owner::{CustomRingTransferInput, Owner},
    sealed,
    selection::{payment_total, widest, Candidate, Funding},
    spends_default_ring,
    spp::HiddenSpend,
    transaction_key, Rail, RailKind, RingTransfer, Spend, Staged, TransferAuthority,
};
use crate::{request::Anchor, trees::BoundAnchor, CustomRing, CustomRingConfig, RingError};

#[async_trait]
pub trait AnonymousSpendSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    /// Signs the ring spend message with RFC 8032 Ed25519.
    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], RingError>;
}

#[async_trait]
impl AnonymousSpendSigner for SigningKey {
    fn public_key(&self) -> PublicKey {
        self.pubkey()
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], RingError> {
        Ok(self.sign_message(message)?)
    }
}

#[async_trait]
impl AnonymousSpendSigner for ed25519_dalek::SigningKey {
    fn public_key(&self) -> PublicKey {
        PublicKey::from_ed25519(self.verifying_key().as_bytes())
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64], RingError> {
        Ok(ed25519_dalek::Signer::sign(self, message).to_bytes())
    }
}

/// The stream is picked when the transfer is proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousPayment {
    pub to: RingAddress,
    pub asset: Mint,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingPayment {
    pub to: RingAddress,
    pub amount: u64,
}

#[must_use = "select the inputs of the move"]
pub struct AnonymousMove<'a> {
    pub ring: CustomRing,
    pub sender: &'a (dyn ShieldedKeys + Send + Sync),
    pub nullifier_key: &'a NullifierKey,
    pub signer: &'a dyn AnonymousSpendSigner,
    pub state: &'a AnonymousRingState,
    pub payer: Address,
    /// The sender's UTXOs on any tree.
    pub utxos: &'a [WalletUtxo],
    pub asset: Mint,
    /// The change returns to the sender.
    pub payments: Vec<RingPayment>,
    pub entry: EntrySpend,
}

/// A default-ring spend publishes the hidden owner's key, a move takes one only when allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntrySpend {
    Refuse,
    Allow,
}

/// The owner's spends on an anonymous ring, no transaction signer names the owner.
pub struct Anonymous<'a> {
    pub(super) owner: Owner<'a>,
    pub(super) signer: &'a dyn AnonymousSpendSigner,
    state: &'a AnonymousRingState,
    /// Keyed by the output slot each payment created.
    payments: Vec<(u32, AnonymousPayment)>,
    exit_token_owner: Option<Address>,
    tag_rng: fn() -> Box<dyn rand_core::CryptoRng + Send>,
}

pub type AnonymousTransfer<'a> = RingTransfer<Anonymous<'a>>;

impl sealed::Sealed for Anonymous<'_> {}

impl Rail for Anonymous<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Anonymous(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    /// The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key.
    pub fn with_anonymous_signer(
        self,
        signer: &'a dyn AnonymousSpendSigner,
        state: &'a AnonymousRingState,
    ) -> RingTransfer<Anonymous<'a>> {
        RingTransfer {
            ring: self.ring,
            rail: Anonymous {
                owner: self.rail,
                signer,
                state,
                payments: Vec::new(),
                exit_token_owner: None,
                tag_rng: os_tag_rng,
            },
        }
    }
}

impl RingTransfer<Anonymous<'_>> {
    /// Every ring output owner other than the sender is paid here, before the transaction is padded.
    pub fn with_payment(mut self, payment: AnonymousPayment) -> Result<Self, RingError> {
        if payment.to.ring_program_id != self.ring.program_id() {
            return Err(RingError::ForeignRingAddress {
                address: payment.to.ring_program_id,
                ring: self.ring.program_id(),
            });
        }
        let transaction = &mut self.rail.owner.transaction;
        // Padding never reorders a slot, the tag follows the output it was built with.
        let slot = u32::try_from(transaction.outputs().len())
            .map_err(|_| zolana_transaction::TransactionError::TooManyOutputs)?;
        transaction.transfer_with_ring(
            &payment.to.recipient,
            payment.asset,
            payment.amount,
            Some(payment.to.ring_program_id),
        )?;
        self.rail.payments.push((slot, payment));
        Ok(self)
    }

    /// Pads to `shape`, else staging pads to the smallest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        let sender = self.rail.owner.sender.address()?;
        self.rail.owner.transaction.pad_utxos(shape, &sender)?;
        Ok(self)
    }

    /// A missing exit token account must be the associated token account of `owner`.
    #[must_use = "use the updated transfer"]
    pub fn with_exit_token_owner(mut self, owner: Address) -> Self {
        self.rail.exit_token_owner = Some(owner);
        self
    }

    #[cfg(test)]
    #[must_use = "use the updated transfer"]
    pub(crate) fn with_tag_rng(
        mut self,
        tag_rng: fn() -> Box<dyn rand_core::CryptoRng + Send>,
    ) -> Self {
        self.rail.tag_rng = tag_rng;
        self
    }

    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        HiddenOwner::of(&self.rail.owner.sender.address()?.signing_pubkey)?.check_signers(signers)
    }
}

impl<'a> AnonymousMove<'a> {
    /// As [`super::DelegateMove::select`], ring UTXOs before an entry spend.
    pub async fn select<P: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<P, I>,
    ) -> Result<AnonymousTransfer<'a>, RingError> {
        let amount = payment_total(self.payments.iter().map(|payment| payment.amount))?;
        let payments = self.payments.len();
        let owner = self.sender.address()?.signing_pubkey;
        let ring = Some(self.ring.program_id());
        let widest_spend = |key: AnonymousKey| widest(payments, |shape| key.serves(shape));
        let max_inputs = widest_spend(AnonymousKey::Commitment).ok_or(RingError::ShapeUnkeyed {
            rail: RingRail::Anonymous,
        })?;
        let funding = Funding {
            utxos: self.utxos,
            asset: self.asset.asset,
            amount,
            max_inputs,
        };
        let ring_only = funding
            .candidates(|utxo| utxo.utxo.owner == owner && utxo.utxo.ring_program_id == ring);
        let entry_width = match self.entry {
            EntrySpend::Allow => widest_spend(AnonymousKey::Entry),
            EntrySpend::Refuse => None,
        };
        let entries = entry_width.map_or_else(Vec::new, |max_inputs| {
            Funding {
                max_inputs,
                ..funding
            }
            .candidates(|utxo| {
                // The prover refuses a spend that mixes ring and default-ring UTXOs.
                utxo.utxo.owner == owner
                    && utxo.is_default_ring_spendable()
                    && carries_no_data([utxo.data_hash, utxo.ring_data_hash])
            })
        });
        let attempts = ring_only
            .iter()
            .map(|candidate| self.attempt(AnonymousKey::Commitment, candidate))
            .chain(
                entries
                    .iter()
                    .map(|candidate| self.attempt(AnonymousKey::Entry, candidate)),
            )
            .collect();
        funding.first_fit(attempts, client).await
    }

    fn attempt(
        &self,
        key: AnonymousKey,
        candidate: &Candidate,
    ) -> Result<AnonymousTransfer<'a>, RingError> {
        let shape = candidate
            .shape(self.payments.len(), |shape| key.serves(shape))
            .ok_or(RingError::ShapeUnkeyed {
                rail: RingRail::Anonymous,
            })?;
        let transaction = ConfidentialTransaction::new_with_ring(
            candidate.utxos.clone(),
            self.payer,
            self.ring.program_id(),
        )?;
        let transfer = RingTransfer::<Owner<'a>>::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(self.nullifier_key),
            transaction,
        })
        .with_anonymous_signer(self.signer, self.state);
        self.payments
            .iter()
            .try_fold(transfer, |transfer, payment| {
                transfer.with_payment(AnonymousPayment {
                    to: payment.to.clone(),
                    asset: self.asset,
                    amount: payment.amount,
                })
            })?
            .with_shape(shape)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AnonymousKey {
    Commitment,
    Entry,
}

impl AnonymousKey {
    pub fn serves(self, shape: Shape) -> bool {
        shape.is_supported()
            && custom_ring_interface::AnonymousSpend {
                inputs: shape.n_inputs(),
                outputs: shape.n_outputs(),
                spends_default_ring: self == Self::Entry,
            }
            .audit_key()
            .is_some()
    }
}

#[derive(Clone, Debug)]
pub(super) struct AnchorWitness {
    pub bound: BoundAnchor,
    pub request: Anchor,
}

struct PinnedProofs<'a> {
    pair: &'a PairAnchor,
    tree: Address,
    proofs: Vec<MerkleProof>,
}

impl PinnedProofs<'_> {
    /// Every pinned leaf proves under the anchor's root, a fault on any leaf fails alike.
    fn anchor(self) -> Result<MerkleProof, RingError> {
        let PinnedProofs { pair, tree, proofs } = self;
        let refused = || leaves_refused(&pair.contact, tree);
        let checked = pair
            .leaves
            .iter()
            .enumerate()
            .map(|(at, leaf)| {
                proofs
                    .iter()
                    .find(|proof| proof.leaf == *leaf)
                    .filter(|proof| proof.check_leaf(leaf, &tree, at).is_ok())
                    .ok_or_else(refused)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let anchor = checked
            .iter()
            .find(|proof| {
                proof.leaf == pair.contact.utxo_hash && proof.leaf_index == pair.contact.leaf_index
            })
            .ok_or_else(refused)?;
        if checked
            .iter()
            .any(|proof| proof.root != anchor.root || proof.root_index != anchor.root_index)
        {
            return Err(refused());
        }
        Ok((*anchor).clone())
    }
}

fn leaves_refused(contact: &SentFirstContact, tree: Address) -> RingError {
    RingError::FirstContactLeavesRefused {
        tree,
        recipient: contact.recipient,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HiddenOwner(pub Address);

pub(crate) struct AnonymousSpend<'a> {
    signer: &'a dyn AnonymousSpendSigner,
    pub epoch: u64,
    pub(super) exit_token_owner: Option<Address>,
    pair: Option<PairAnchor>,
    pub first_contacts: Vec<PendingFirstContact>,
}

/// The leaf index is known only after confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PendingFirstContact {
    pub recipient: zolana_keypair::X25519Pubkey,
    pub tree_id: u16,
    pub utxo_hash: [u8; 32],
    pub slot_secret: [u8; 32],
    pub first_nullifier: [u8; 32],
    pub slot_index: u8,
    pub epoch: u64,
    pub index: custom_ring_interface::stream::TagIndex,
    pub asset: Address,
    pub amount: u64,
}

impl core::fmt::Debug for PendingFirstContact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            recipient: _,
            tree_id,
            utxo_hash: _,
            slot_secret: _,
            first_nullifier: _,
            slot_index,
            epoch,
            index,
            asset,
            amount,
        } = self;
        f.debug_struct("PendingFirstContact")
            .field("recipient", &REDACTED)
            .field("tree_id", tree_id)
            .field("utxo_hash", &REDACTED)
            .field("slot_secret", &REDACTED)
            .field("first_nullifier", &REDACTED)
            .field("slot_index", slot_index)
            .field("epoch", epoch)
            .field("index", index)
            .field("asset", asset)
            .field("amount", amount)
            .finish()
    }
}

impl PendingFirstContact {
    pub fn confirm(self, leaf_index: u64) -> SentFirstContact {
        SentFirstContact {
            recipient: self.recipient,
            tree_id: self.tree_id,
            leaf_index,
            utxo_hash: self.utxo_hash,
            slot_secret: self.slot_secret,
            first_nullifier: self.first_nullifier,
            slot_index: self.slot_index,
            epoch: self.epoch,
            index: self.index,
            asset: self.asset,
            amount: self.amount,
        }
    }
}

impl AnonymousSpend<'_> {
    pub(super) fn anchor_tree(&self) -> Option<Address> {
        self.pair
            .as_ref()
            .map(|pair| pda::tree(pair.contact.tree_id))
    }

    /// `None` without a pair payment, else the path under a root the program reads.
    pub(super) async fn anchor<R: AsyncRpc + ?Sized>(
        &self,
        client: &R,
    ) -> Result<Option<AnchorWitness>, RingError> {
        let Some(pair) = &self.pair else {
            return Ok(None);
        };
        let contact = &pair.contact;
        let tree = pda::tree(contact.tree_id);
        let proofs = match client
            .get_merkle_proofs(tree, pair.leaves.to_vec(), None)
            .await
        {
            Err(ClientError::Indexer(_)) => return Err(leaves_refused(contact, tree)),
            answer => answer?.proofs,
        };
        let proof = PinnedProofs { pair, tree, proofs }.anchor()?;
        let bound = BoundAnchor {
            tree,
            root_index: proof.root_index,
            root: proof.root,
        };
        if !bound.holds(client).await? {
            return Err(RingError::FirstContactRootStale {
                tree,
                root_index: proof.root_index,
            });
        }
        Ok(Some(AnchorWitness {
            bound,
            request: Anchor {
                tree_id: tree_id_field(contact.tree_id),
                asset: hash_bytes(contact.asset.as_array())?,
                amount: right_align(&contact.amount.to_be_bytes()),
                slot_secret: contact.slot_secret,
                first_nullifier: contact.first_nullifier,
                slot_index: contact.slot_index,
                epoch: contact.epoch,
                index: contact.index.get(),
                path_index: contact.leaf_index,
                path: proof.path,
            },
        }))
    }

    /// The signature over the final transfer, the ring program appends its configured co-signer.
    pub(super) async fn sign(
        &self,
        ring: CustomRing,
        config: &CustomRingConfig,
        inputs: &SppProofInputs,
    ) -> Result<HiddenSpend, RingError> {
        let message = ring_spend_message(&ring.program_id(), &inputs.message_hash()?);
        Ok(HiddenSpend {
            owner: zolana_client::prover::transact::HiddenOwnerAuthorization {
                public_key: self.signer.public_key().as_ed25519()?,
                signature: self.signer.sign(&message).await?,
            },
            co_signer: config.co_signer.as_ref().map(|co_signer| co_signer.signer),
            exit_token_owner: self.exit_token_owner,
        })
    }
}

impl HiddenOwner {
    pub(crate) fn of(key: &PublicKey) -> Result<Self, RingError> {
        Ok(Self(Address::new_from_array(key.as_ed25519()?)))
    }

    pub(crate) fn check_signers(
        self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        match signers.into_iter().any(|signer| signer == self.0) {
            true => Err(RingError::AnonymousPublicSignerLinksOwner),
            false => Ok(()),
        }
    }
}

impl Anonymous<'_> {
    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        ring: CustomRing,
        client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        if config.mode != RingMode::Anonymous {
            return Err(RingError::NotAnonymousRing);
        }
        let keys = self.owner.sender;
        let sender = keys.address()?;
        if self.signer.public_key() != sender.signing_pubkey {
            return Err(RingError::AnonymousSignerMismatch);
        }
        let owner = HiddenOwner::of(&sender.signing_pubkey)?;
        let co_signer = config.co_signer.as_ref().map(|co_signer| co_signer.signer);
        owner.check_signers(core::iter::once(self.owner.transaction.payer()).chain(co_signer))?;
        self.owner.check_settlement_accounts()?;
        let exit_token_owner = AnonymousExits {
            transfers: &self.owner.transaction.interface_transfers()?,
            hidden_owner: &owner.0,
            named_owner: self.exit_token_owner,
        }
        .token_owner(client)
        .await?;
        // Tags bind slots, the slot order is fixed before any stream is read.
        let mut transaction = self.owner.transaction.clone();
        transaction.pad_to_canonical_shape(&sender)?;
        let epoch = tag_epoch(client.get_slot().await?);
        let first_nullifier = *transaction.first_nullifier();
        let tx_viewing_key = transaction_key(keys, first_nullifier)?;
        let issued: Vec<u32> = self
            .state
            .issued()
            .iter()
            .map(|issued| issued.index)
            .collect();
        let mut slots = AnonymousSlots::new(keys.ring_change_key(&ring.program_id())?)
            .with_ring_address_keys(keys.ring_address_keys(&ring.program_id(), &issued)?);
        let mut allocation = TagAllocation::new(self.state, epoch);
        let mut rng = (self.tag_rng)();
        let mut pair = None;
        for (slot, payment) in &self.payments {
            let tag = allocation.allocate(&payment.to, &mut *rng)?;
            let position = match tag.stream {
                PaymentStream::Inbox => StreamPosition::Inbox(tag.index),
                PaymentStream::Pair(anchor) => {
                    pair = Some(*anchor);
                    StreamPosition::Pair(tag.index)
                }
            };
            slots = slots.with_payment(
                *slot,
                StreamPayment {
                    recipient: payment.to.recipient.viewing_pubkey,
                    tag: tag.tag,
                    position,
                },
            )?;
        }
        let rail = RingOutputRail::new(tx_viewing_key, RingDelivery::Anonymous(Box::new(slots)));
        let proof_inputs = rail.encrypt(transaction, &sender)?;
        check_anonymous_slots(&proof_inputs)?;
        if let Some(index) = proof_inputs
            .input_utxos
            .iter()
            .position(|input| !input.is_dummy() && input.utxo.owner != sender.signing_pubkey)
        {
            return Err(RingError::MixedOwners { index });
        }
        check_entry_inputs(&proof_inputs)?;
        check_audit_key(&proof_inputs)?;
        let first_contacts = InboxPayments {
            rail: &rail,
            inputs: &proof_inputs,
            first_nullifier: &first_nullifier,
            epoch,
        }
        .first_contacts()?;
        Ok(Staged {
            proof_inputs,
            rail,
            sender,
            authority: TransferAuthority {
                owner: self.owner.nullifier_key.cloned(),
            },
            owner_signers: Vec::new(),
            interface_transfer_accounts: self.owner.interface_transfer_accounts.clone(),
            spend: Spend::Anonymous(Box::new(AnonymousSpend {
                signer: self.signer,
                epoch,
                exit_token_owner,
                pair,
                first_contacts,
            })),
        })
    }
}

struct InboxPayments<'a> {
    rail: &'a RingOutputRail,
    inputs: &'a SppProofInputs,
    first_nullifier: &'a [u8; 32],
    epoch: u64,
}

impl InboxPayments<'_> {
    fn first_contacts(self) -> Result<Vec<PendingFirstContact>, RingError> {
        let RingDelivery::Anonymous(slots) = self.rail.delivery() else {
            return Ok(Vec::new());
        };
        let mut contacts = Vec::new();
        for (slot, output) in (0u32..).zip(&self.inputs.output_utxos) {
            let Some(StreamPayment {
                recipient,
                position: StreamPosition::Inbox(index),
                ..
            }) = slots.payment(slot)
            else {
                continue;
            };
            let secret: SlotSecret =
                self.rail
                    .slot_secret(&recipient, self.first_nullifier, slot)?;
            contacts.push(PendingFirstContact {
                recipient,
                tree_id: self.inputs.output_tree_id,
                utxo_hash: output.hash(self.inputs.output_tree_id)?,
                slot_secret: *secret.as_bytes(),
                first_nullifier: *self.first_nullifier,
                slot_index: u8::try_from(slot)
                    .map_err(|_| zolana_transaction::TransactionError::TooManyOutputs)?,
                epoch: self.epoch,
                index,
                asset: output.asset.asset,
                amount: output.amount,
            });
        }
        Ok(contacts)
    }
}

/// The anonymous rail takes uncached noncompact notes only, real outputs owned by Ed25519 keys.
fn check_anonymous_slots(inputs: &SppProofInputs) -> Result<(), RingError> {
    let input_open = inputs
        .input_utxos
        .iter()
        .any(|input| input.cache_slot.is_some() || input.is_compact() || input.is_address());
    let output_open = inputs.output_utxos.iter().any(|output| {
        output.cache_slot.is_some()
            || output.is_compact()
            || (!output.is_dummy()
                && output.owner_address.is_none_or(|address| {
                    address.signing_pubkey.curve().ok() != Some(Curve::Ed25519)
                }))
    });
    match input_open || output_open {
        true => Err(RingError::InvalidAnonymousSlot),
        false => Ok(()),
    }
}

/// A default-ring spend past the entry class must split, any other spend needs a commitment key.
fn check_audit_key(inputs: &SppProofInputs) -> Result<(), RingError> {
    let default_ring = spends_default_ring(&inputs.input_utxos);
    let published = inputs
        .input_utxos
        .iter()
        .filter(|input| !input.is_compact())
        .count();
    let spend = custom_ring_interface::AnonymousSpend {
        inputs: published,
        outputs: inputs.output_utxos.len(),
        spends_default_ring: default_ring,
    };
    match (spend.audit_key(), default_ring) {
        (Some(_), _) => Ok(()),
        (None, true) => Err(RingError::DefaultRingSpendTooWide { inputs: published }),
        (None, false) => Err(RingError::ShapeUnkeyed {
            rail: RingRail::Anonymous,
        }),
    }
}

/// The entry key rebuilds every spent UTXO from its opening.
fn check_entry_inputs(inputs: &SppProofInputs) -> Result<(), RingError> {
    if !spends_default_ring(&inputs.input_utxos) {
        return Ok(());
    }
    inputs
        .input_utxos
        .iter()
        .enumerate()
        .filter(|(_, input)| !input.is_dummy())
        .try_for_each(|(index, input)| {
            if input.utxo.ring_program_id.is_some() {
                Err(RingError::EntryRingInput { index })
            } else if carries_no_data([input.data_hash, input.ring_data_hash]) {
                Ok(())
            } else {
                Err(RingError::EntryInputData { index })
            }
        })
}

fn carries_no_data(hashes: [Option<[u8; 32]>; 2]) -> bool {
    hashes
        .iter()
        .all(|hash| hash.is_none_or(|hash| hash == [0; 32]))
}

fn os_tag_rng() -> Box<dyn rand_core::CryptoRng + Send> {
    Box::new(rand_core::UnwrapErr(rand_core::OsRng))
}

struct AnonymousExits<'a> {
    transfers: &'a [SettlementTransfer],
    hidden_owner: &'a Address,
    named_owner: Option<Address>,
}

struct SplExit {
    mint: Address,
    token_account: Address,
}

impl AnonymousExits<'_> {
    /// The owner SPP binds for the SPL withdrawal, `None` without one.
    async fn token_owner<R: AsyncRpc + ?Sized>(
        self,
        client: &R,
    ) -> Result<Option<Address>, RingError> {
        let withdrawals = self
            .transfers
            .iter()
            .filter(|transfer| !transfer.is_deposit());
        if self.named_owner.is_some()
            && !withdrawals
                .clone()
                .any(|transfer| matches!(transfer, SettlementTransfer::Spl { .. }))
        {
            return Err(ClientError::AnonymousExitTokenOwnerMismatch.into());
        }
        let mut token_owner: Option<Address> = None;
        for transfer in withdrawals {
            match *transfer {
                SettlementTransfer::Sol {
                    user_sol_account: recipient,
                    ..
                } => self.check_sol_exit(client, recipient).await?,
                SettlementTransfer::Spl {
                    mint,
                    user_spl_token: token_account,
                    ..
                } => {
                    let owner = self
                        .spl_exit_owner(
                            client,
                            SplExit {
                                mint,
                                token_account,
                            },
                        )
                        .await?;
                    if let Some(named) = self.named_owner.filter(|named| *named != owner) {
                        return Err(RingError::AnonymousExitNamedOwnerMismatch {
                            token_account,
                            named,
                            owner,
                        });
                    }
                    if token_owner
                        .replace(owner)
                        .is_some_and(|previous| previous != owner)
                    {
                        return Err(ShieldedPoolError::AnonymousExitDestinationsDiffer.into());
                    }
                }
            }
        }
        Ok(token_owner)
    }

    async fn check_sol_exit<R: AsyncRpc + ?Sized>(
        &self,
        client: &R,
        recipient: Address,
    ) -> Result<(), RingError> {
        if recipient == *self.hidden_owner {
            return Err(RingError::AnonymousExitLinksOwner(recipient));
        }
        // SPP reads a missing account as a system account without data.
        let Some(account) = client.get_account(recipient).await? else {
            return Ok(());
        };
        AnonymousExitDestination::Sol {
            recipient: &recipient,
            owner: &account.owner,
            data_len: account.data.len(),
        }
        .named_key()
        .map_err(|refusal| exit_refused(refusal, recipient))?;
        Ok(())
    }

    async fn spl_exit_owner<R: AsyncRpc + ?Sized>(
        &self,
        client: &R,
        exit: SplExit,
    ) -> Result<Address, RingError> {
        let SplExit {
            mint,
            token_account,
        } = exit;
        let invalid = || RingError::AnonymousExitTokenAccountInvalid(token_account);
        let (control, token_program) = match client.get_account(token_account).await? {
            Some(account) => (
                token_account_state(&account, &mint)
                    .ok_or_else(invalid)?
                    .control,
                account.owner,
            ),
            // The associated token program creates it with the named owner and no other authority.
            None => {
                let owner = self.named_owner.ok_or_else(invalid)?;
                let token_program = client
                    .get_account(mint)
                    .await?
                    .map(|mint| mint.owner)
                    .filter(is_token_program)
                    .ok_or_else(invalid)?;
                if pda::associated_token_address_with_program(&owner, &mint, &token_program)
                    != token_account
                {
                    return Err(invalid());
                }
                (
                    TokenAccountControl::SoleOwner(owner.to_bytes()),
                    token_program,
                )
            }
        };
        let owner = Address::new_from_array(*control.owner());
        let hidden = *self.hidden_owner;
        // An associated token account stays derivable from its first owner.
        let associated = pda::associated_token_address_with_program(&hidden, &mint, &token_program);
        if [token_account, owner].contains(&hidden) || associated == token_account {
            return Err(RingError::AnonymousExitLinksOwner(token_account));
        }
        AnonymousExitDestination::Spl {
            token_account: &token_account,
            control: &control,
        }
        .named_key()
        .map_err(|refusal| exit_refused(refusal, token_account))?;
        Ok(owner)
    }
}

fn token_account_state(account: &Account, mint: &Address) -> Option<TokenAccountState> {
    if !is_token_program(&account.owner) {
        return None;
    }
    TokenAccountState::unpack(&account.data)
        .ok()
        .filter(|state| state.mint == mint.to_bytes())
}

fn is_token_program(program: &Address) -> bool {
    [SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID].contains(program.as_array())
}

fn exit_refused(refusal: ShieldedPoolError, destination: Address) -> RingError {
    match refusal {
        ShieldedPoolError::AnonymousExitAccountHasData => {
            RingError::AnonymousExitAccountHasData(destination)
        }
        ShieldedPoolError::AnonymousExitTokenAccountOnCurve => {
            RingError::AnonymousExitTokenAccountOnCurve(destination)
        }
        ShieldedPoolError::AnonymousExitTokenAccountShared => {
            RingError::AnonymousExitTokenAccountShared(destination)
        }
        refusal => RingError::AnonymousExitRefused {
            destination,
            refusal,
        },
    }
}
