//! Anonymous ring streams, each read by exact tag per epoch.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    ops::RangeInclusive,
};

use custom_ring_interface::{
    stream::{
        tag_epoch, DeliveredSlot, InboxKey, PairKey, RingTag, SlotSecret, TagIndex, K_PAIR_EPOCHS,
    },
    RingDepositAuditCapsule,
};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_signature::Signature;
use zolana_event_parser::decode_encrypted_ring_deposit_output_data;
use zolana_keypair::{Pairing, PairingRow, RingAddress, X25519Pubkey};
use zolana_ring_policy::ring_id_field;
use zolana_transaction::{
    exactly_one, verify_owned, AssetRegistry, DecryptionResult, DepositPayload, EncryptedScheme,
    OutputSlot, RingDeliveredCandidate, RingDeliveryContext, RingDeliveryRequest, RingRecipientKey,
    ShieldedKeys, ShieldedTransaction, TransactionError, TransactionKeyRequest, WalletUtxo,
    REDACTED,
};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerRpcConfig},
    tags::{indices, IndexerReads, TagWindow, DEFAULT_TAG_WINDOW},
};

/// Unused addresses past the highest issued or used one that a scan still reads.
pub const ADDRESS_GAP: u32 = 20;

/// Every scan reads the inbox stream of each issued address, the count bounds its cost.
pub const MAX_ISSUED_ADDRESSES: u32 = 1 << 10;

pub const DECOYS_PER_TREE: usize = 64;

pub const ANONYMOUS_RING_STATE_VERSION: u32 = 3;

/// Epochs one fetch reads, the next fetch continues past them.
pub const MAX_FETCH_EPOCHS: u64 = 1 << 10;

/// Epochs a pair stream lives past its last payment, the same at both ends.
pub const PAIR_IDLE_EPOCHS: u64 = 8;

/// Counters a deposit scan reads past the highest holding a deposit of the wallet.
pub const DEPOSIT_GAP: u64 = 2 * DEFAULT_TAG_WINDOW;

/// Decoy paths fetched beside the anchor's, the leaves of its tree a scan already holds.
pub const ANCHOR_DECOYS: usize = 7;

const ANCHOR_DECOY_DOMAIN: &[u8] = b"zolana/ring-anchor-decoy/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedAddress {
    pub index: u32,
    /// The rows its recipient tracks first contacts under.
    pub pairing: Pairing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReceivedAnchor {
    pub address_index: u32,
    pub pair_key: [u8; 32],
    /// The epoch of the first contact's inbox tag.
    pub epoch: u64,
    /// The epoch of the newest pair payment found, `epoch` until one.
    pub last_epoch: u64,
    pub asset: Address,
    pub amount: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SentFirstContact {
    /// The recipient address's key, the inbox stream it took derives from it.
    pub recipient: X25519Pubkey,
    pub tree_id: u16,
    pub leaf_index: u64,
    pub utxo_hash: [u8; 32],
    pub slot_secret: [u8; 32],
    pub first_nullifier: [u8; 32],
    pub slot_index: u8,
    /// The inbox tag's epoch.
    pub epoch: u64,
    pub index: TagIndex,
    pub asset: Address,
    pub amount: u64,
}

impl fmt::Debug for ReceivedAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedAnchor")
            .field("address_index", &self.address_index)
            .field("epoch", &self.epoch)
            .field("last_epoch", &self.last_epoch)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SentFirstContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentFirstContact")
            .field("recipient", &REDACTED)
            .field("tree_id", &self.tree_id)
            .field("leaf_index", &REDACTED)
            .field("utxo_hash", &REDACTED)
            .field("slot_secret", &REDACTED)
            .field("first_nullifier", &REDACTED)
            .field("slot_index", &self.slot_index)
            .field("epoch", &self.epoch)
            .field("index", &self.index)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .finish()
    }
}

impl ReceivedAnchor {
    pub fn live_through(&self) -> u64 {
        pair_live_through(self.epoch, self.last_epoch)
    }
}

impl SentFirstContact {
    /// Live without a later pair payment.
    pub fn is_live(&self, epoch: u64) -> bool {
        (self.epoch..=pair_live_through(self.epoch, self.epoch)).contains(&epoch)
    }

    fn same_leaf(&self, other: &Self) -> bool {
        self.tree_id == other.tree_id
            && self.leaf_index == other.leaf_index
            && self.utxo_hash == other.utxo_hash
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SentPair {
    contact: SentFirstContact,
    /// The newest pair payment a scan saw the wallet make on it.
    last_epoch: u64,
    /// Every read of the anchor names these decoys, `None` until a scan pins them.
    decoys: Option<[[u8; 32]; ANCHOR_DECOYS]>,
}

impl fmt::Debug for SentPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentPair")
            .field("contact", &self.contact)
            .field("last_epoch", &self.last_epoch)
            .field("decoys", &REDACTED)
            .finish()
    }
}

impl SentPair {
    fn live(&self, epoch: u64) -> bool {
        (self.contact.epoch..=pair_live_through(self.contact.epoch, self.last_epoch))
            .contains(&epoch)
    }

    /// The lowest ranked leaves beside the anchor, `None` while fewer than `ANCHOR_DECOYS`.
    fn pin(&self, pool: &[DecoyLeaf]) -> Option<[[u8; 32]; ANCHOR_DECOYS]> {
        let anchor = self.contact.utxo_hash;
        let decoys = by_rank(
            &self.contact.slot_secret,
            pool.iter()
                .map(|leaf| leaf.hash)
                .filter(|hash| *hash != anchor),
        );
        decoys.get(..ANCHOR_DECOYS)?.try_into().ok()
    }

    fn anchor(&self) -> Option<PairAnchor> {
        let leaves = by_rank(
            &self.contact.slot_secret,
            self.decoys?.into_iter().chain([self.contact.utxo_hash]),
        );
        Some(PairAnchor {
            contact: self.contact,
            leaves: leaves.try_into().ok()?,
        })
    }
}

/// A live first contact whose decoys a scan pinned.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairAnchor {
    pub contact: SentFirstContact,
    /// Every read of the anchor names these leaves, in order.
    pub leaves: [[u8; 32]; ANCHOR_DECOYS + 1],
}

impl fmt::Debug for PairAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairAnchor")
            .field("contact", &self.contact)
            .field("leaves", &REDACTED)
            .finish()
    }
}

/// Distinct `hashes` in the order of a rank keyed by the slot secret, no reader of a request
/// can tell the anchor from a decoy.
fn by_rank(slot_secret: &[u8; 32], hashes: impl IntoIterator<Item = [u8; 32]>) -> Vec<[u8; 32]> {
    let mut ranked: Vec<([u8; 32], [u8; 32])> = hashes
        .into_iter()
        .map(|hash| {
            let rank = Sha256::new()
                .chain_update(ANCHOR_DECOY_DOMAIN)
                .chain_update(slot_secret)
                .chain_update(hash)
                .finalize()
                .into();
            (rank, hash)
        })
        .collect();
    ranked.sort_unstable();
    ranked.dedup();
    ranked.into_iter().map(|(_, hash)| hash).collect()
}

/// A proof bounds a pair by its first contact, the idle rule by its last payment.
fn pair_live_through(first: u64, last: u64) -> u64 {
    first
        .saturating_add(K_PAIR_EPOCHS - 1)
        .min(last.saturating_add(PAIR_IDLE_EPOCHS - 1))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecoyLeaf {
    pub leaf_index: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
pub struct AnonymousRingState {
    ring: Address,
    creation_epoch: u64,
    /// Sorted by index.
    issued: Vec<IssuedAddress>,
    /// The last epoch every stream was read through, `None` before the first scan.
    scanned_epoch: Option<u64>,
    received: Vec<ReceivedAnchor>,
    /// One per recipient key.
    sent: Vec<SentPair>,
    deposit_next: u64,
    decoys: BTreeMap<u16, Vec<DecoyLeaf>>,
}

impl fmt::Debug for AnonymousRingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnonymousRingState")
            .field("ring", &self.ring)
            .field("creation_epoch", &self.creation_epoch)
            .field("issued", &self.issued)
            .field("scanned_epoch", &self.scanned_epoch)
            .field("received", &self.received)
            .field("sent", &self.sent)
            .field("deposit_next", &self.deposit_next)
            .field("decoys", &REDACTED)
            .finish()
    }
}

impl AnonymousRingState {
    /// A wallet that never scanned `ring`, its first scan reads from the ring's creation epoch.
    pub fn new(ring: Address, creation_epoch: u64) -> Self {
        Self {
            ring,
            creation_epoch,
            issued: Vec::new(),
            scanned_epoch: None,
            received: Vec::new(),
            sent: Vec::new(),
            deposit_next: 0,
            decoys: BTreeMap::new(),
        }
    }

    /// Takes a version 1 store's issued count, its addresses rescan from creation.
    pub fn migrate_v1(
        ring: Address,
        creation_epoch: u64,
        issued_addresses: u32,
    ) -> Result<Self, ClientError> {
        let mut state = Self::new(ring, creation_epoch);
        for index in 0..issued_addresses {
            state.issue(index, Pairing::default())?;
        }
        Ok(state)
    }

    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn creation_epoch(&self) -> u64 {
        self.creation_epoch
    }

    pub fn issued(&self) -> &[IssuedAddress] {
        &self.issued
    }

    pub fn scanned_epoch(&self) -> Option<u64> {
        self.scanned_epoch
    }

    pub fn received(&self) -> &[ReceivedAnchor] {
        &self.received
    }

    pub fn sent(&self) -> impl Iterator<Item = &SentFirstContact> {
        self.sent.iter().map(|sent| &sent.contact)
    }

    pub fn deposit_next(&self) -> u64 {
        self.deposit_next
    }

    pub fn decoys(&self, tree_id: u16) -> &[DecoyLeaf] {
        self.decoys.get(&tree_id).map_or(&[], Vec::as_slice)
    }

    /// Every later scan reads the inbox stream of `index`, the pairing replaces an earlier one.
    pub fn issue(&mut self, index: u32, pairing: Pairing) -> Result<(), ClientError> {
        if index >= MAX_ISSUED_ADDRESSES {
            return Err(ClientError::TooManyIssuedAddresses {
                count: u64::from(index) + 1,
            });
        }
        match self
            .issued
            .binary_search_by_key(&index, |issued| issued.index)
        {
            Ok(position) => self.issued[position].pairing = pairing,
            Err(position) => self
                .issued
                .insert(position, IssuedAddress { index, pairing }),
        }
        Ok(())
    }

    /// `None` until [`Self::issue`] issues `index`.
    pub fn address<K: ShieldedKeys + ?Sized>(
        &self,
        keys: &K,
        index: u32,
    ) -> Result<Option<RingAddress>, ClientError> {
        let Some(issued) = self.issued.iter().find(|issued| issued.index == index) else {
            return Ok(None);
        };
        let address_key = exactly_one(keys.ring_address_keys(&self.ring, &[index])?)?;
        Ok(Some(RingAddress {
            recipient: zolana_keypair::ShieldedAddress {
                viewing_pubkey: address_key,
                ..keys.address()?
            },
            ring_program_id: self.ring,
            pairing: issued.pairing.clone(),
        }))
    }

    /// Live in `epoch`, pinned or not.
    pub fn first_contact(&self, recipient: &X25519Pubkey, epoch: u64) -> Option<&SentFirstContact> {
        self.live_sent(recipient, epoch).map(|sent| &sent.contact)
    }

    /// The anchor a payment to `recipient` in `epoch` may pair on, live with its decoys pinned.
    pub fn pair_anchor(&self, recipient: &X25519Pubkey, epoch: u64) -> Option<PairAnchor> {
        self.live_sent(recipient, epoch)?.anchor()
    }

    fn live_sent(&self, recipient: &X25519Pubkey, epoch: u64) -> Option<&SentPair> {
        self.sent
            .iter()
            .find(|sent| sent.contact.recipient == *recipient && sent.live(epoch))
    }

    /// A confirmed inbox payment becomes its address's newest first contact.
    pub fn record_first_contact(&mut self, contact: SentFirstContact) {
        let recorded = SentPair {
            contact,
            last_epoch: contact.epoch,
            decoys: None,
        };
        match self
            .sent
            .iter_mut()
            .find(|sent| sent.contact.recipient == contact.recipient)
        {
            Some(sent) if sent.contact.same_leaf(&contact) => {}
            Some(sent) if sent.contact.epoch <= contact.epoch => *sent = recorded,
            Some(_) => {}
            None => self.sent.push(recorded),
        }
    }

    /// The next payment to `recipient` takes its inbox stream.
    pub fn retire_first_contact(&mut self, recipient: &X25519Pubkey) {
        self.sent
            .retain(|sent| sent.contact.recipient != *recipient);
    }

    /// Only the first contacts of `stored` stay, a pin it holds never changes.
    pub fn keep_first_contacts(&mut self, stored: &AnonymousRingState) {
        let scanned = std::mem::take(&mut self.sent);
        let through = self.scanned_epoch;
        self.sent = stored
            .sent
            .iter()
            .filter_map(|kept| {
                match scanned
                    .iter()
                    .find(|sent| sent.contact.same_leaf(&kept.contact))
                {
                    Some(sent) => Some(SentPair {
                        contact: kept.contact,
                        last_epoch: sent.last_epoch.max(kept.last_epoch),
                        decoys: kept.decoys.or(sent.decoys),
                    }),
                    // A pair the scan already found idle stays dropped.
                    None => through
                        .is_none_or(|epoch| {
                            pair_live_through(kept.contact.epoch, kept.last_epoch) > epoch
                        })
                        .then_some(*kept),
                }
            })
            .collect();
    }

    fn pin_anchors(&mut self) {
        for sent in &mut self.sent {
            if sent.decoys.is_none() {
                let pool = self
                    .decoys
                    .get(&sent.contact.tree_id)
                    .map_or(&[][..], Vec::as_slice);
                sent.decoys = sent.pin(pool);
            }
        }
    }

    /// A pair tag of a live first contact among the outputs of the wallet's own spend.
    fn note_pair_payment(&mut self, spend: &ShieldedTransaction) -> Result<(), ClientError> {
        let landed = tag_epoch(spend.slot);
        let tags: HashSet<[u8; 32]> = spend
            .output_slots
            .iter()
            .map(|slot| slot.view_tag)
            .collect();
        for sent in &mut self.sent {
            // A proof of epoch e lands in e, or flagged in e + 1.
            let epochs: Vec<u64> = [landed.saturating_sub(1), landed]
                .into_iter()
                .filter(|epoch| *epoch > sent.last_epoch && sent.live(*epoch))
                .collect();
            if epochs.is_empty() {
                continue;
            }
            let pair = PairKey::derive(&SlotSecret::new(sent.contact.slot_secret)?)?;
            for epoch in epochs {
                for index in TagIndex::all() {
                    if tags.contains(&pair.tag(epoch, index)?.field()) {
                        sent.last_epoch = epoch;
                    }
                }
            }
        }
        Ok(())
    }

    /// Drops the pair streams no later payment can reach.
    fn prune(&mut self, open: u64) {
        let scanned = self.scanned_epoch;
        self.received
            .retain(|anchor| scanned.is_none_or(|scanned| anchor.live_through() > scanned));
        self.sent.retain(|sent| sent.live(open));
    }

    /// At most [`MAX_FETCH_EPOCHS`], the first one past the last scanned.
    fn fetch_epochs(&self, slot: u64) -> RangeInclusive<u64> {
        let first = self
            .scanned_epoch
            .map_or(self.creation_epoch, |epoch| epoch.saturating_add(1));
        first..=tag_epoch(slot).min(first.saturating_add(MAX_FETCH_EPOCHS - 1))
    }

    /// An epoch past every slot's, or a scan before the ring's creation, reads nothing again.
    fn check_epochs(&self) -> Result<(), ClientError> {
        let last = tag_epoch(u64::MAX);
        let refused = |epoch| Err(ClientError::AnonymousRingEpoch { epoch });
        if self.creation_epoch > last {
            return refused(self.creation_epoch);
        }
        match self.scanned_epoch {
            Some(epoch) if epoch > last || epoch < self.creation_epoch => refused(epoch),
            _ => Ok(()),
        }
    }

    fn address_window(&self) -> u32 {
        self.issued
            .last()
            .map_or(0, |issued| issued.index + 1)
            .saturating_add(ADDRESS_GAP)
            .min(MAX_ISSUED_ADDRESSES)
    }

    fn pairing(&self, index: u32) -> Pairing {
        self.issued
            .iter()
            .find(|issued| issued.index == index)
            .map_or_else(Pairing::default, |issued| issued.pairing.clone())
    }

    /// Keeps the lowest and highest leaf of each tree and spreads the rest evenly between them.
    fn remember_decoys<'a>(
        &mut self,
        transactions: impl IntoIterator<Item = &'a ShieldedTransaction>,
    ) {
        let ring = self.ring;
        // Only a leaf shaped as a first contact hides one among its decoys.
        for slot in transactions
            .into_iter()
            .filter(|tx| tx.ring_program_id == Some(ring))
            .flat_map(|tx| &tx.output_slots)
            .filter(|slot| {
                slot.ring_delivered_body(EncryptedScheme::RingAnonymous)
                    .is_some()
            })
        {
            let context = &slot.output_context;
            let leaves = self.decoys.entry(context.tree_id).or_default();
            let leaf = DecoyLeaf {
                leaf_index: context.leaf_index,
                hash: context.hash,
            };
            if let Err(position) = leaves.binary_search(&leaf) {
                leaves.insert(position, leaf);
            }
        }
        for leaves in self.decoys.values_mut() {
            if leaves.len() > DECOYS_PER_TREE {
                let last = leaves.len() - 1;
                *leaves = (0..DECOYS_PER_TREE)
                    .map(|k| leaves[k * last / (DECOYS_PER_TREE - 1)])
                    .collect();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousStream {
    Inbox {
        address_index: u32,
        epoch: u64,
        index: TagIndex,
    },
    Pair {
        address_index: u32,
        epoch: u64,
        index: TagIndex,
    },
    Change {
        first_nullifier: [u8; 32],
    },
    Merge {
        first_nullifier: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousRingUtxo {
    pub utxo_hash: [u8; 32],
    pub stream: AnonymousStream,
}

#[derive(Clone, Debug)]
pub struct AnonymousRingScan {
    /// Scanned through the last epoch the indexer holds every landing of.
    pub state: AnonymousRingState,
    /// Every ring note found and every spend read, no later fetch reads a pending note again.
    pub decrypted: DecryptionResult,
    pub utxos: Vec<AnonymousRingUtxo>,
    /// Anchors the scan added whose pair stream is still live.
    pub anchors: Vec<ReceivedAnchor>,
}

/// Reads every inbox, pair, deposit, change and merge stream of the wallet, each derived by `keys`.
#[must_use]
pub struct AnonymousRingSync<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    config: Option<IndexerRpcConfig>,
    deposit_payload: DepositPayload,
    held: Vec<HeldUtxo>,
    default_ring_spends: Vec<ShieldedTransaction>,
}

struct HeldUtxo {
    ring_program_id: Option<Address>,
    nullifier: [u8; 32],
    utxo_hash: [u8; 32],
}

impl<'a, K: ShieldedKeys + ?Sized> AnonymousRingSync<'a, K> {
    pub fn new(keys: &'a K, assets: &'a AssetRegistry) -> Self {
        Self {
            keys,
            assets,
            config: None,
            deposit_payload: audit_capsule_payload,
            held: Vec::new(),
            default_ring_spends: Vec::new(),
        }
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// A framing of the deposit ciphertexts other than the audit capsule.
    pub fn with_deposit_payload(mut self, deposit_payload: DepositPayload) -> Self {
        self.deposit_payload = deposit_payload;
        self
    }

    /// The change scan asks for the nullifiers of the scanned ring's UTXOs among them alone.
    pub fn with_held_utxos<'u>(mut self, utxos: impl IntoIterator<Item = &'u WalletUtxo>) -> Self {
        self.held = utxos
            .into_iter()
            .map(|held| HeldUtxo {
                ring_program_id: held.utxo.ring_program_id,
                nullifier: held.nullifier,
                utxo_hash: held.utxo_hash,
            })
            .collect();
        self
    }

    /// Spends the default-ring sync read, their ring change opens with no nullifier query.
    pub fn with_default_ring_spends(mut self, transactions: Vec<ShieldedTransaction>) -> Self {
        self.default_ring_spends = transactions;
        self
    }

    /// Reads at most [`MAX_FETCH_EPOCHS`] epochs after `state`'s last, through the epoch of `slot`.
    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        state: &AnonymousRingState,
        slot: u64,
    ) -> Result<AnonymousRingScan, ClientError> {
        let epochs = state.fetch_epochs(slot);
        let open = *epochs.end();
        let mut scan = Scan {
            sync: self,
            state: state.clone(),
            ring_id: ring_id_field(state.ring.as_array())?,
            epochs,
            decrypted: DecryptionResult::default(),
            utxos: Vec::new(),
            added: Vec::new(),
            transactions: Vec::new(),
            tagged: HashSet::new(),
            spends: HashSet::new(),
            deposits: HashSet::new(),
        };
        let mut reads = IndexerReads::configured(indexer, self.config);
        scan.streams(&mut reads).await?;
        // The change frontier starts from every note found, deposits included.
        scan.deposits(&mut reads).await?;
        scan.change(&mut reads).await?;
        let Scan {
            mut state,
            decrypted,
            utxos,
            added,
            transactions,
            ..
        } = scan;
        state.remember_decoys(&transactions);
        // A transfer proven in epoch e lands until e + 1 ends under the previous-epoch flag.
        let persisted = reads.persisted_slot().map_or(open, tag_epoch).min(open);
        if let Some(scanned) = persisted
            .checked_sub(2)
            .filter(|epoch| *epoch >= state.creation_epoch && state.scanned_epoch < Some(*epoch))
        {
            state.scanned_epoch = Some(scanned);
        }
        state.prune(open);
        state.pin_anchors();
        let anchors = state
            .received
            .iter()
            .filter(|anchor| added.contains(&anchor.pair_key))
            .copied()
            .collect();
        Ok(AnonymousRingScan {
            state,
            decrypted,
            utxos,
            anchors,
        })
    }
}

/// The recipient's ciphertext inside an audited deposit's capsule, `None` without a capsule.
pub fn audit_capsule_payload(bytes: &[u8]) -> Result<Option<&[u8]>, TransactionError> {
    Ok(RingDepositAuditCapsule::parse(bytes)?.map(|capsule| capsule.recipient_ciphertext))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    Inbox,
    /// The position of its anchor among the state's received ones.
    Pair(usize),
}

#[derive(Clone, Copy)]
struct TagSite {
    address_index: u32,
    epoch: u64,
    index: TagIndex,
    kind: StreamKind,
}

impl TagSite {
    fn stream(self) -> AnonymousStream {
        let Self {
            address_index,
            epoch,
            index,
            kind,
        } = self;
        match kind {
            StreamKind::Inbox => AnonymousStream::Inbox {
                address_index,
                epoch,
                index,
            },
            StreamKind::Pair(_) => AnonymousStream::Pair {
                address_index,
                epoch,
                index,
            },
        }
    }
}

struct Hit<'t> {
    tx: &'t ShieldedTransaction,
    output_index: u32,
    site: TagSite,
    tag: Option<RingTag>,
}

const TAGS_PER_ROUND: usize = 4 * crate::tags::TAGS_PER_REQUEST;

#[derive(Default)]
struct AddressStreams {
    inbox: Option<InboxKey>,
    pairs: Vec<PairRead>,
}

struct PairRead {
    anchor: usize,
    key: PairKey,
    epochs: RangeInclusive<u64>,
}

impl AddressStreams {
    /// Whole epochs per chunk, past `TAGS_PER_ROUND` tags only when one epoch alone is.
    fn chunks(
        &self,
        address_index: u32,
        epochs: RangeInclusive<u64>,
    ) -> Result<Vec<HashMap<[u8; 32], TagSite>>, ClientError> {
        let mut chunks = Vec::new();
        let mut sites = HashMap::new();
        for epoch in epochs {
            let site = |index, kind| TagSite {
                address_index,
                epoch,
                index,
                kind,
            };
            let mut epoch_sites = Vec::new();
            if let Some(inbox) = &self.inbox {
                for index in TagIndex::all() {
                    epoch_sites.push((
                        inbox.tag(epoch, index)?.field(),
                        site(index, StreamKind::Inbox),
                    ));
                }
            }
            for pair in self
                .pairs
                .iter()
                .filter(|pair| pair.epochs.contains(&epoch))
            {
                for index in TagIndex::all() {
                    epoch_sites.push((
                        pair.key.tag(epoch, index)?.field(),
                        site(index, StreamKind::Pair(pair.anchor)),
                    ));
                }
            }
            if !sites.is_empty() && sites.len() + epoch_sites.len() > TAGS_PER_ROUND {
                chunks.push(std::mem::take(&mut sites));
            }
            sites.extend(epoch_sites);
        }
        if !sites.is_empty() {
            chunks.push(sites);
        }
        Ok(chunks)
    }
}

struct Scan<'s, 'a, K: ?Sized> {
    sync: &'s AnonymousRingSync<'a, K>,
    state: AnonymousRingState,
    ring_id: [u8; 32],
    epochs: RangeInclusive<u64>,
    decrypted: DecryptionResult,
    utxos: Vec<AnonymousRingUtxo>,
    /// Pair keys of the anchors the scan added.
    added: Vec<[u8; 32]>,
    transactions: Vec<ShieldedTransaction>,
    tagged: HashSet<(Signature, Option<u16>)>,
    /// Spends, a tagged transaction that spends a note still carries change.
    spends: HashSet<(Signature, Option<u16>)>,
    /// A deposit counts once, a replay under a later counter moves nothing.
    deposits: HashSet<[u8; 32]>,
}

impl<K: ShieldedKeys + ?Sized> Scan<'_, '_, K> {
    /// Rounds repeat until none adds an address or a live pair epoch, a request names one address.
    async fn streams<I: AsyncRpc + ?Sized>(
        &mut self,
        reads: &mut IndexerReads<'_, I>,
    ) -> Result<(), ClientError> {
        let mut read_addresses = BTreeSet::new();
        let mut read_through = Vec::new();
        loop {
            let round = self.round(&mut read_addresses, &mut read_through)?;
            if round.is_empty() {
                return Ok(());
            }
            for (address_index, streams) in round {
                for sites in streams.chunks(address_index, self.epochs.clone())? {
                    let tags: Vec<[u8; 32]> = sites.keys().copied().collect();
                    let transactions = reads.transactions(&tags).await?;
                    self.open_streams(&sites, &transactions)?;
                    self.transactions
                        .extend(fresh(&mut self.tagged, transactions));
                }
            }
        }
    }

    /// The inbox streams and pair epochs of this fetch no earlier round read, by address.
    fn round(
        &self,
        read_addresses: &mut BTreeSet<u32>,
        read_through: &mut Vec<Option<u64>>,
    ) -> Result<BTreeMap<u32, AddressStreams>, ClientError> {
        let mut round: BTreeMap<u32, AddressStreams> = BTreeMap::new();
        let addresses: Vec<u32> = (0..self.state.address_window())
            .filter(|index| read_addresses.insert(*index))
            .collect();
        if !addresses.is_empty() {
            let keys = self
                .sync
                .keys
                .ring_address_keys(&self.state.ring, &addresses)?;
            check_count(keys.len(), addresses.len())?;
            for (index, key) in addresses.into_iter().zip(keys) {
                round.entry(index).or_default().inbox =
                    Some(InboxKey::derive(&self.ring_id, key.as_bytes())?);
            }
        }
        read_through.resize(self.state.received.len(), None);
        for (anchor, (received, through)) in self
            .state
            .received
            .iter()
            .zip(read_through.iter_mut())
            .enumerate()
        {
            let from = through.map_or(received.epoch.max(*self.epochs.start()), |epoch| {
                epoch.saturating_add(1)
            });
            let to = received.live_through().min(*self.epochs.end());
            if from > to {
                continue;
            }
            *through = Some(to);
            round
                .entry(received.address_index)
                .or_default()
                .pairs
                .push(PairRead {
                    anchor,
                    key: PairKey::from_bytes(received.pair_key)?,
                    epochs: from..=to,
                });
        }
        Ok(round)
    }

    /// Opens every output under a derived tag, an admitted inbox hit anchors a pair stream.
    fn open_streams(
        &mut self,
        sites: &HashMap<[u8; 32], TagSite>,
        transactions: &[ShieldedTransaction],
    ) -> Result<(), ClientError> {
        let mut hits = Vec::new();
        let mut requests = Vec::new();
        for tx in transactions
            .iter()
            .filter(|tx| tx.ring_program_id == Some(self.state.ring))
        {
            let Some(context) = RingDeliveryContext::of(tx) else {
                continue;
            };
            for (position, slot) in tx.output_slots.iter().enumerate() {
                let Some(site) = sites.get(&slot.view_tag) else {
                    continue;
                };
                // Any address holder writes under its tags, only an anonymous body earns a secret.
                if slot
                    .ring_delivered_body(EncryptedScheme::RingAnonymous)
                    .is_none()
                {
                    continue;
                }
                let output_index = slot_index(position)?;
                hits.push(Hit {
                    tx,
                    output_index,
                    site: *site,
                    tag: RingTag::from_owner_tag(&slot.view_tag),
                });
                requests.push(RingDeliveryRequest {
                    recipient: RingRecipientKey::Address {
                        ring: self.state.ring,
                        index: site.address_index,
                    },
                    tx_viewing_pk: context.tx_viewing_pk,
                    salt: context.salt,
                    output_index,
                    first_nullifier: context.first_nullifier,
                });
            }
        }
        if requests.is_empty() {
            return Ok(());
        }
        let secrets = self.sync.keys.ring_delivery_secrets(&requests)?;
        check_count(secrets.len(), requests.len())?;
        let mut candidates = Vec::with_capacity(hits.len());
        let mut secrets_of = Vec::with_capacity(hits.len());
        for (hit, secret) in hits.iter().zip(secrets) {
            let secret = SlotSecret::new(secret)?;
            secrets_of.push((hit.site, secret.clone()));
            candidates.push(RingDeliveredCandidate {
                tx: hit.tx,
                slot_index: hit.output_index,
                tag: hit.tag,
                slot_secret: secret,
            });
        }
        let finds = self.decrypted.extend_ring_delivered(
            self.sync.keys,
            self.sync.assets,
            transactions,
            &candidates,
        )?;
        for find in finds {
            let (site, secret) = &secrets_of[find.candidate];
            self.utxos.push(AnonymousRingUtxo {
                utxo_hash: find.utxo_hash,
                stream: site.stream(),
            });
            if let StreamKind::Pair(anchor) = site.kind {
                if let Some(anchor) = self.state.received.get_mut(anchor) {
                    anchor.last_epoch = anchor.last_epoch.max(site.epoch);
                }
                continue;
            }
            if !self
                .state
                .issued
                .iter()
                .any(|issued| issued.index == site.address_index)
            {
                self.state.issue(site.address_index, Pairing::default())?;
            }
            if !self
                .state
                .pairing(site.address_index)
                .admits(&find.asset_address, find.amount)
            {
                continue;
            }
            let pair_key = *PairKey::derive(secret)?.as_bytes();
            if self
                .state
                .received
                .iter()
                .any(|anchor| anchor.pair_key == pair_key)
            {
                continue;
            }
            self.state.received.push(ReceivedAnchor {
                address_index: site.address_index,
                pair_key,
                epoch: site.epoch,
                last_epoch: site.epoch,
                asset: find.asset_address,
                amount: find.amount,
            });
            self.added.push(pair_key);
        }
        Ok(())
    }

    /// The default-ring spends open first, then every spend of a ring UTXO, round after round.
    async fn change<I: AsyncRpc + ?Sized>(
        &mut self,
        reads: &mut IndexerReads<'_, I>,
    ) -> Result<(), ClientError> {
        let change_key = self.sync.keys.ring_change_key(&self.state.ring)?;
        let viewing_pubkey = self.sync.keys.address()?.viewing_pubkey;
        let ring = Some(self.state.ring);
        let mut queried: HashSet<[u8; 32]> = HashSet::new();
        let mut frontier: Vec<[u8; 32]> = self
            .sync
            .held
            .iter()
            .filter(|held| held.ring_program_id == ring)
            .map(|held| held.nullifier)
            .collect();
        let mut spends = fresh(&mut self.spends, self.sync.default_ring_spends.clone());
        loop {
            self.open_change(&spends, &change_key, viewing_pubkey)?;
            self.open_merges(&spends)?;
            self.transactions.extend(spends);
            frontier.extend(
                self.decrypted
                    .utxos
                    .iter()
                    .filter(|utxo| utxo.utxo.ring_program_id == ring)
                    .map(|utxo| utxo.nullifier),
            );
            frontier.retain(|nullifier| queried.insert(*nullifier));
            if frontier.is_empty() {
                return Ok(());
            }
            spends = fresh(&mut self.spends, reads.spends(&frontier).await?);
            frontier.clear();
        }
    }

    /// Opens change under the re-derived transaction key, every spend read marks its inputs spent.
    fn open_change(
        &mut self,
        spends: &[ShieldedTransaction],
        change_key: &X25519Pubkey,
        viewing_pubkey: X25519Pubkey,
    ) -> Result<(), ClientError> {
        let own: Vec<(&ShieldedTransaction, RingDeliveryContext)> = spends
            .iter()
            .filter(|tx| tx.ring_program_id == Some(self.state.ring))
            .filter_map(|tx| RingDeliveryContext::of(tx).map(|context| (tx, context)))
            .collect();
        let mut candidates = Vec::new();
        let mut first_nullifiers = Vec::new();
        let mut signed = Vec::new();
        if !own.is_empty() {
            let requests: Vec<TransactionKeyRequest> = own
                .iter()
                .map(|(_, context)| TransactionKeyRequest {
                    viewing_pubkey,
                    first_nullifier: context.first_nullifier,
                })
                .collect();
            let tx_keys = self.sync.keys.transaction_keys(&requests)?;
            check_count(tx_keys.len(), requests.len())?;
            for ((tx, context), tx_key) in own.iter().zip(tx_keys) {
                // Another holder of the note signed it, its outputs are not the wallet's change.
                if tx_key.pubkey() != context.tx_viewing_pk {
                    continue;
                }
                signed.push(*tx);
                let agreement = tx_key.ecdh(change_key).map_err(TransactionError::from)?;
                for (position, slot) in tx.output_slots.iter().enumerate() {
                    if slot
                        .ring_delivered_body(EncryptedScheme::RingAnonymous)
                        .is_none()
                    {
                        continue;
                    }
                    let output_index = slot_index(position)?;
                    let secret = DeliveredSlot {
                        agreement: &agreement,
                        tx_viewing_pk: context.tx_viewing_pk.as_bytes(),
                        recipient_viewing_pk: change_key.as_bytes(),
                        salt: &context.salt,
                        output_index,
                        first_nullifier: &context.first_nullifier,
                    }
                    .secret()?;
                    candidates.push(RingDeliveredCandidate {
                        tx,
                        slot_index: output_index,
                        tag: RingTag::from_owner_tag(&slot.view_tag),
                        slot_secret: secret,
                    });
                    first_nullifiers.push(context.first_nullifier);
                }
            }
        }
        // An earlier payment extends the window a later one is checked against.
        signed.sort_by_key(|tx| tx.slot);
        for tx in signed {
            self.state.note_pair_payment(tx)?;
        }
        let finds = self.decrypted.extend_ring_delivered(
            self.sync.keys,
            self.sync.assets,
            spends,
            &candidates,
        )?;
        for find in finds {
            self.utxos.push(AnonymousRingUtxo {
                utxo_hash: find.utxo_hash,
                stream: AnonymousStream::Change {
                    first_nullifier: first_nullifiers[find.candidate],
                },
            });
        }
        Ok(())
    }

    /// A merge output opens under keys the owner's nullifier key derives.
    fn open_merges(&mut self, spends: &[ShieldedTransaction]) -> Result<(), ClientError> {
        let merges: Vec<ShieldedTransaction> = spends
            .iter()
            .filter(|tx| tx.ring_program_id == Some(self.state.ring) && tx.may_be_merge())
            .cloned()
            .collect();
        if merges.is_empty() {
            return Ok(());
        }
        self.decrypted
            .extend(self.sync.keys, &merges, self.sync.assets)?;
        let held: HashSet<[u8; 32]> = self
            .decrypted
            .utxos
            .iter()
            .map(|utxo| utxo.utxo_hash)
            .collect();
        for merge in &merges {
            let Some(&first_nullifier) = merge.nullifiers.first() else {
                continue;
            };
            self.utxos.extend(
                merge
                    .output_slots
                    .iter()
                    .map(|slot| slot.output_context.hash)
                    .filter(|hash| held.contains(hash))
                    .map(|utxo_hash| AnonymousRingUtxo {
                        utxo_hash,
                        stream: AnonymousStream::Merge { first_nullifier },
                    }),
            );
        }
        Ok(())
    }

    /// Reads through `DEPOSIT_GAP` counters past the highest deposit of the wallet in any ring.
    async fn deposits<I: AsyncRpc + ?Sized>(
        &mut self,
        reads: &mut IndexerReads<'_, I>,
    ) -> Result<(), ClientError> {
        let mut start = self.state.deposit_next;
        while start < self.state.deposit_next.saturating_add(DEPOSIT_GAP) {
            let counters: Vec<u64> = indices(start).collect();
            let tags = self.sync.keys.sender_view_tags(&counters)?;
            check_count(tags.len(), counters.len())?;
            let window = TagWindow::new(start, tags);
            let deposits = reads.deposits(&window.tags()).await?;
            if let Some(highest) = self.open_deposits(&window, deposits)? {
                self.state.deposit_next = self.state.deposit_next.max(highest.saturating_add(1));
            }
            let Some(next) = start.checked_add(DEFAULT_TAG_WINDOW) else {
                return Ok(());
            };
            start = next;
        }
        Ok(())
    }

    /// Keeps the ring's deposits, the highest counter holding a new deposit of the wallet.
    fn open_deposits(
        &mut self,
        window: &TagWindow,
        deposits: Vec<ShieldedTransaction>,
    ) -> Result<Option<u64>, ClientError> {
        let mut unwrapped = Vec::with_capacity(deposits.len());
        let mut ours = Vec::new();
        for mut tx in deposits {
            let Some(ring) = tx.output_slots.first().and_then(deposit_ring) else {
                continue;
            };
            let framing = tx
                .output_slots
                .iter_mut()
                .try_for_each(|slot| slot.unwrap_ring_deposit(&ring, self.sync.deposit_payload));
            match framing {
                Ok(()) if ring == self.state.ring => ours.push(tx.clone()),
                Ok(()) => {}
                // A depositor's malformed framing opens to nothing.
                Err(TransactionError::RingDepositCapsule(_)) => continue,
                Err(error) => return Err(error.into()),
            }
            unwrapped.push(tx);
        }
        let mut opened = DecryptionResult::default();
        opened.extend(self.sync.keys, &unwrapped, self.sync.assets)?;
        let owned: HashSet<[u8; 32]> = verify_owned(self.sync.keys, &opened)?
            .utxos
            .into_iter()
            .map(|utxo| utxo.utxo_hash)
            .collect();
        self.decrypted
            .extend(self.sync.keys, &ours, self.sync.assets)?;
        let held: HashSet<[u8; 32]> = self.sync.held.iter().map(|held| held.utxo_hash).collect();
        let mut counted: Vec<(u64, [u8; 32])> = unwrapped
            .iter()
            .flat_map(|tx| &tx.output_slots)
            .filter(|slot| {
                owned.contains(&slot.output_context.hash)
                    && !held.contains(&slot.output_context.hash)
            })
            .filter_map(|slot| Some((window.index_of(&slot.view_tag)?, slot.output_context.hash)))
            .collect();
        // A replay of a held or counted deposit under a later tag moves nothing.
        counted.sort_unstable();
        Ok(counted
            .into_iter()
            .filter(|(_, hash)| self.deposits.insert(*hash))
            .map(|(counter, _)| counter)
            .max())
    }
}

/// The ring a deposit output names, `None` for any other output.
fn deposit_ring(slot: &OutputSlot) -> Option<Address> {
    decode_encrypted_ring_deposit_output_data(&slot.payload)
        .ok()
        .map(|output| Address::new_from_array(output.ring_program_id))
}

fn fresh(
    seen: &mut HashSet<(Signature, Option<u16>)>,
    transactions: Vec<ShieldedTransaction>,
) -> Vec<ShieldedTransaction> {
    transactions
        .into_iter()
        .filter(|tx| seen.insert((tx.tx_signature, tx.event_index)))
        .collect()
}

fn slot_index(position: usize) -> Result<u32, ClientError> {
    u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs.into())
}

fn check_count(got: usize, want: usize) -> Result<(), ClientError> {
    if got != want {
        return Err(TransactionError::IncompleteDerivation { got, want }.into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentStream {
    Inbox,
    Pair(Box<PairAnchor>),
}

/// The tag a payment publishes in the epoch its proof binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentTag {
    pub stream: PaymentStream,
    pub epoch: u64,
    pub index: TagIndex,
    pub tag: RingTag,
}

/// One transaction's payment tags in one epoch, at most one of them pair-anchored.
#[must_use]
pub struct TagAllocation<'a> {
    state: &'a AnonymousRingState,
    epoch: u64,
    /// The indexes this transaction took, by stream key.
    taken: HashMap<[u8; 32], BTreeSet<TagIndex>>,
    paired: bool,
}

impl<'a> TagAllocation<'a> {
    /// `state` is the sender's, its first contacts anchor pair payments.
    pub fn new(state: &'a AnonymousRingState, epoch: u64) -> Self {
        Self {
            state,
            epoch,
            taken: HashMap::new(),
            paired: false,
        }
    }

    /// The pair stream of an admitted pinned first contact, else the inbox stream, at an index
    /// `rng` draws.
    pub fn allocate<R: CryptoRng + ?Sized>(
        &mut self,
        address: &RingAddress,
        rng: &mut R,
    ) -> Result<PaymentTag, ClientError> {
        if address.ring_program_id != self.state.ring {
            return Err(ClientError::ForeignRingAddress {
                address_ring: address.ring_program_id,
                ring: self.state.ring,
            });
        }
        let recipient = address.recipient.viewing_pubkey;
        let anchor = self
            .state
            .pair_anchor(&recipient, self.epoch)
            .filter(|anchor| {
                !self.paired
                    && address
                        .pairing
                        .admits(&anchor.contact.asset, anchor.contact.amount)
            });
        if let Some(anchor) = anchor {
            let pair = PairKey::derive(&SlotSecret::new(anchor.contact.slot_secret)?)?;
            let index = self.draw(*pair.as_bytes(), rng);
            self.paired = true;
            return Ok(PaymentTag {
                stream: PaymentStream::Pair(Box::new(anchor)),
                epoch: self.epoch,
                index,
                tag: pair.tag(self.epoch, index)?,
            });
        }
        let inbox = InboxKey::derive(
            &ring_id_field(self.state.ring.as_array())?,
            recipient.as_bytes(),
        )?;
        let index = self.draw(*inbox.as_bytes(), rng);
        Ok(PaymentTag {
            stream: PaymentStream::Inbox,
            epoch: self.epoch,
            index,
            tag: inbox.tag(self.epoch, index)?,
        })
    }

    /// Uniform over the indexes this transaction left free, over every index once none is.
    fn draw<R: CryptoRng + ?Sized>(&mut self, stream: [u8; 32], rng: &mut R) -> TagIndex {
        let taken = self.taken.entry(stream).or_default();
        let free: Vec<TagIndex> = TagIndex::all()
            .filter(|index| !taken.contains(index))
            .collect();
        let pool = match free.is_empty() {
            true => TagIndex::all().collect(),
            false => free,
        };
        let index = pool[uniform_below(rng, pool.len())];
        taken.insert(index);
        index
    }
}

/// A draw past the largest multiple of `bound` is drawn again, the rest are uniform.
fn uniform_below<R: CryptoRng + ?Sized>(rng: &mut R, bound: usize) -> usize {
    let bound = bound as u64;
    let zone = u64::MAX - u64::MAX % bound;
    loop {
        let value = rng.next_u64();
        if value < zone {
            return (value % bound) as usize;
        }
    }
}

/// The persisted form, field values in hex and addresses in base58.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StateJson {
    version: u32,
    ring: String,
    creation_epoch: u64,
    issued: Vec<IssuedJson>,
    scanned_epoch: Option<u64>,
    received: Vec<AnchorJson>,
    sent: Vec<ContactJson>,
    deposit_next: u64,
    decoys: Vec<DecoysJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IssuedJson {
    index: u32,
    pairing: Vec<RowJson>,
}

/// Amounts as decimal strings, a TypeScript number rounds a u64 past `Number.MAX_SAFE_INTEGER`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RowJson {
    mint: String,
    min_amount: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AnchorJson {
    address_index: u32,
    pair_key: String,
    epoch: u64,
    last_epoch: u64,
    asset: String,
    amount: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ContactJson {
    recipient: String,
    tree_id: u16,
    leaf_index: u64,
    utxo_hash: String,
    slot_secret: String,
    first_nullifier: String,
    slot_index: u8,
    epoch: u64,
    index: u8,
    asset: String,
    amount: String,
    last_epoch: u64,
    decoys: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DecoysJson {
    tree_id: u16,
    leaves: Vec<LeafJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LeafJson {
    leaf_index: u64,
    hash: String,
}

impl AnonymousRingState {
    /// Its slot secrets and pair keys link the wallet's payments, store it as key material.
    pub fn to_json(&self) -> String {
        let state = StateJson {
            version: ANONYMOUS_RING_STATE_VERSION,
            ring: self.ring.to_string(),
            creation_epoch: self.creation_epoch,
            issued: self
                .issued
                .iter()
                .map(|issued| IssuedJson {
                    index: issued.index,
                    pairing: issued
                        .pairing
                        .rows()
                        .iter()
                        .map(|row| RowJson {
                            mint: row.mint.to_string(),
                            min_amount: row.min_amount.to_string(),
                        })
                        .collect(),
                })
                .collect(),
            scanned_epoch: self.scanned_epoch,
            received: self
                .received
                .iter()
                .map(|anchor| AnchorJson {
                    address_index: anchor.address_index,
                    pair_key: hex::encode(anchor.pair_key),
                    epoch: anchor.epoch,
                    last_epoch: anchor.last_epoch,
                    asset: anchor.asset.to_string(),
                    amount: anchor.amount.to_string(),
                })
                .collect(),
            sent: self
                .sent
                .iter()
                .map(
                    |SentPair {
                         contact,
                         last_epoch,
                         decoys,
                     }| ContactJson {
                        recipient: hex::encode(contact.recipient.as_bytes()),
                        tree_id: contact.tree_id,
                        leaf_index: contact.leaf_index,
                        utxo_hash: hex::encode(contact.utxo_hash),
                        slot_secret: hex::encode(contact.slot_secret),
                        first_nullifier: hex::encode(contact.first_nullifier),
                        slot_index: contact.slot_index,
                        epoch: contact.epoch,
                        index: contact.index.get(),
                        asset: contact.asset.to_string(),
                        amount: contact.amount.to_string(),
                        last_epoch: *last_epoch,
                        decoys: decoys.map(|decoys| decoys.iter().map(hex::encode).collect()),
                    },
                )
                .collect(),
            deposit_next: self.deposit_next,
            decoys: self
                .decoys
                .iter()
                .map(|(tree_id, leaves)| DecoysJson {
                    tree_id: *tree_id,
                    leaves: leaves
                        .iter()
                        .map(|leaf| LeafJson {
                            leaf_index: leaf.leaf_index,
                            hash: hex::encode(leaf.hash),
                        })
                        .collect(),
                })
                .collect(),
        };
        serde_json::to_string(&state).expect("a struct of strings, integers and vectors serializes")
    }

    /// Another version fails with [`ClientError::AnonymousRingStateVersion`], a rescan rebuilds all
    /// but the sent first contacts.
    pub fn from_json(text: &str) -> Result<Self, ClientError> {
        #[derive(Deserialize)]
        struct Versioned {
            version: u32,
        }
        let invalid = |error: String| ClientError::AnonymousRingState(error);
        let Versioned { version } = serde_json::from_str(text).map_err(unparsed)?;
        if version != ANONYMOUS_RING_STATE_VERSION {
            return Err(ClientError::AnonymousRingStateVersion { version });
        }
        let state: StateJson = serde_json::from_str(text).map_err(unparsed)?;
        let address = |text: &str| {
            text.parse::<Address>()
                .map_err(|error| invalid(error.to_string()))
        };
        let amount = |text: &str| {
            text.parse::<u64>()
                .map_err(|error| invalid(error.to_string()))
        };
        let mut restored = Self::new(address(&state.ring)?, state.creation_epoch);
        for issued in state.issued {
            if restored
                .issued
                .binary_search_by_key(&issued.index, |known| known.index)
                .is_ok()
            {
                return Err(invalid(format!(
                    "issued names index {} twice",
                    issued.index
                )));
            }
            let rows = issued
                .pairing
                .iter()
                .map(|row| {
                    Ok(PairingRow {
                        mint: address(&row.mint)?,
                        min_amount: amount(&row.min_amount)?,
                    })
                })
                .collect::<Result<Vec<_>, ClientError>>()?;
            restored.issue(issued.index, Pairing::new(rows)?)?;
        }
        restored.scanned_epoch = state.scanned_epoch;
        restored.check_epochs()?;
        restored.received = state
            .received
            .iter()
            .map(|anchor| {
                Ok(ReceivedAnchor {
                    address_index: anchor.address_index,
                    pair_key: HexField {
                        name: "pairKey",
                        text: &anchor.pair_key,
                    }
                    .field()?,
                    epoch: anchor.epoch,
                    last_epoch: anchor.last_epoch,
                    asset: address(&anchor.asset)?,
                    amount: amount(&anchor.amount)?,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        restored.sent = state
            .sent
            .iter()
            .map(|contact| {
                let recorded = SentFirstContact {
                    recipient: X25519Pubkey::from_bytes(
                        HexField {
                            name: "recipient",
                            text: &contact.recipient,
                        }
                        .decode()?,
                    )?,
                    tree_id: contact.tree_id,
                    leaf_index: contact.leaf_index,
                    utxo_hash: HexField {
                        name: "utxoHash",
                        text: &contact.utxo_hash,
                    }
                    .decode()?,
                    slot_secret: HexField {
                        name: "slotSecret",
                        text: &contact.slot_secret,
                    }
                    .field()?,
                    first_nullifier: HexField {
                        name: "firstNullifier",
                        text: &contact.first_nullifier,
                    }
                    .decode()?,
                    slot_index: contact.slot_index,
                    epoch: contact.epoch,
                    index: TagIndex::new(contact.index)?,
                    asset: address(&contact.asset)?,
                    amount: amount(&contact.amount)?,
                };
                let decoys = contact
                    .decoys
                    .as_deref()
                    .map(|decoys| pinned_decoys(decoys, &recorded.utxo_hash))
                    .transpose()?;
                Ok(SentPair {
                    contact: recorded,
                    last_epoch: contact.last_epoch,
                    decoys,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        let recipients: HashSet<&X25519Pubkey> = restored
            .sent
            .iter()
            .map(|sent| &sent.contact.recipient)
            .collect();
        if recipients.len() != restored.sent.len() {
            return Err(invalid(
                "sent holds two first contacts for one recipient".to_owned(),
            ));
        }
        restored.deposit_next = state.deposit_next;
        for decoys in state.decoys {
            let leaves = decoys
                .leaves
                .iter()
                .map(|leaf| {
                    Ok(DecoyLeaf {
                        leaf_index: leaf.leaf_index,
                        hash: HexField {
                            name: "hash",
                            text: &leaf.hash,
                        }
                        .decode()?,
                    })
                })
                .collect::<Result<BTreeSet<_>, ClientError>>()?;
            if leaves.len() > DECOYS_PER_TREE {
                return Err(invalid(format!(
                    "decoys of tree {} hold more than {DECOYS_PER_TREE} leaves",
                    decoys.tree_id
                )));
            }
            if restored
                .decoys
                .insert(decoys.tree_id, leaves.into_iter().collect())
                .is_some()
            {
                return Err(invalid(format!(
                    "decoys name tree {} twice",
                    decoys.tree_id
                )));
            }
        }
        Ok(restored)
    }
}

/// Distinct leaves beside the anchor, as `SentPair::pin` keeps them.
fn pinned_decoys(
    texts: &[String],
    anchor: &[u8; 32],
) -> Result<[[u8; 32]; ANCHOR_DECOYS], ClientError> {
    let decoys = texts
        .iter()
        .map(|text| {
            HexField {
                name: "decoys",
                text,
            }
            .decode()
        })
        .collect::<Result<Vec<[u8; 32]>, ClientError>>()?;
    let distinct: BTreeSet<&[u8; 32]> = decoys.iter().collect();
    match decoys.as_slice().try_into() {
        Ok(pinned) if distinct.len() == ANCHOR_DECOYS && !distinct.contains(anchor) => Ok(pinned),
        _ => Err(ClientError::AnonymousRingState(format!(
            "decoys are not {ANCHOR_DECOYS} distinct leaves beside the anchor"
        ))),
    }
}

/// An error names the field alone, its text may be a slot secret or a pair key.
struct HexField<'a> {
    name: &'static str,
    text: &'a str,
}

impl HexField<'_> {
    fn decode<const N: usize>(self) -> Result<[u8; N], ClientError> {
        hex::decode(self.text)
            .ok()
            .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
            .ok_or_else(|| {
                ClientError::AnonymousRingState(format!("{} is not {N} hex bytes", self.name))
            })
    }

    /// Slot secrets and pair keys are Poseidon outputs.
    fn field(self) -> Result<[u8; 32], ClientError> {
        let name = self.name;
        let bytes = self.decode()?;
        SlotSecret::new(bytes)
            .map(|_| bytes)
            .map_err(|_| ClientError::AnonymousRingState(format!("{name} is not a field element")))
    }
}

/// A serde message can quote the value it refused, the position alone names the fault.
fn unparsed(error: serde_json::Error) -> ClientError {
    ClientError::AnonymousRingState(format!(
        "{:?} at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fetch_reads_at_most_max_fetch_epochs() {
        let state = AnonymousRingState::new(Address::new_from_array([1; 32]), 3);
        assert_eq!(state.fetch_epochs(u64::MAX), 3..=3 + MAX_FETCH_EPOCHS - 1);
        assert_eq!(MAX_FETCH_EPOCHS, 1 << 10);
    }
}
