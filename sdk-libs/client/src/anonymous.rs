//! Anonymous ring streams, each read by exact tag per epoch.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
};

use custom_ring_interface::{
    stream::{
        tag_epoch, DeliveredSlot, InboxKey, PairKey, RingTag, SlotSecret, TagIndex, J_INBOX,
        K_PAIR_EPOCHS,
    },
    RingDepositAuditCapsule,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use zolana_keypair::{Pairing, PairingRow, RingAddress, X25519Pubkey};
use zolana_ring_policy::ring_id_field;
use zolana_transaction::{
    exactly_one, AssetRegistry, DecryptionResult, DepositPayload, EncryptedScheme,
    RingDeliveredCandidate, RingDeliveryContext, RingDeliveryRequest, RingRecipientKey,
    ShieldedKeys, ShieldedTransaction, TransactionError, TransactionKeyRequest,
};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, IndexerRpcConfig},
    tags::{indices, occupied, IndexerReads, TagWindow},
};

/// Unused addresses past the highest issued or used one that a scan still reads.
pub const ADDRESS_GAP: u32 = 20;

/// Every scan reads the inbox stream of each issued address, the count bounds its cost.
pub const MAX_ISSUED_ADDRESSES: u32 = 1 << 10;

pub const DECOYS_PER_TREE: usize = 64;

pub const ANONYMOUS_RING_STATE_VERSION: u32 = 2;

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
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SentFirstContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SentFirstContact")
            .field("recipient", &self.recipient)
            .field("tree_id", &self.tree_id)
            .field("leaf_index", &self.leaf_index)
            .field("utxo_hash", &self.utxo_hash)
            .field("slot_index", &self.slot_index)
            .field("epoch", &self.epoch)
            .field("index", &self.index)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

impl SentFirstContact {
    /// Live from its own epoch for `K_PAIR_EPOCHS` epochs.
    pub fn is_live(&self, epoch: u64) -> bool {
        epoch >= self.epoch && epoch - self.epoch < K_PAIR_EPOCHS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecoyLeaf {
    pub leaf_index: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousRingState {
    ring: Address,
    creation_epoch: u64,
    /// Sorted by index.
    issued: Vec<IssuedAddress>,
    /// The last epoch every stream was read through, `None` before the first scan.
    scanned_epoch: Option<u64>,
    received: Vec<ReceivedAnchor>,
    /// One per recipient key.
    sent: Vec<SentFirstContact>,
    deposit_next: u64,
    decoys: BTreeMap<u16, Vec<DecoyLeaf>>,
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

    pub fn sent(&self) -> &[SentFirstContact] {
        &self.sent
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

    /// The live first contact to `recipient`, the anchor a payment in `epoch` may pair on.
    pub fn first_contact(&self, recipient: &X25519Pubkey, epoch: u64) -> Option<&SentFirstContact> {
        self.sent
            .iter()
            .find(|contact| contact.recipient == *recipient && contact.is_live(epoch))
    }

    /// A confirmed inbox payment becomes its address's newest first contact.
    pub fn record_first_contact(&mut self, contact: SentFirstContact) {
        match self
            .sent
            .iter_mut()
            .find(|sent| sent.recipient == contact.recipient)
        {
            Some(sent) if sent.epoch <= contact.epoch => *sent = contact,
            Some(_) => {}
            None => self.sent.push(contact),
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
        for slot in transactions.into_iter().flat_map(|tx| &tx.output_slots) {
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
pub struct AnonymousRingNote {
    pub utxo_hash: [u8; 32],
    pub stream: AnonymousStream,
}

#[derive(Clone, Debug)]
pub struct AnonymousRingScan {
    /// Scanned through the last epoch the indexer holds every landing of.
    pub state: AnonymousRingState,
    /// Every ring note found and every spend read, no later fetch reads a pending note again.
    pub decrypted: DecryptionResult,
    pub notes: Vec<AnonymousRingNote>,
    /// Anchors the scan added, each opens a pair stream.
    pub anchors: Vec<ReceivedAnchor>,
}

/// Reads every inbox, pair, deposit and change stream of the wallet, each derived by `keys`.
#[must_use]
pub struct AnonymousRingSync<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    config: Option<IndexerRpcConfig>,
    deposit_payload: DepositPayload,
    known_nullifiers: Vec<[u8; 32]>,
}

impl<'a, K: ShieldedKeys + ?Sized> AnonymousRingSync<'a, K> {
    pub fn new(keys: &'a K, assets: &'a AssetRegistry) -> Self {
        Self {
            keys,
            assets,
            config: None,
            deposit_payload: audit_capsule_payload,
            known_nullifiers: Vec::new(),
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

    /// Nullifiers of the wallet's ring and default-ring notes, a spend of either carries change.
    pub fn with_known_nullifiers(mut self, nullifiers: Vec<[u8; 32]>) -> Self {
        self.known_nullifiers = nullifiers;
        self
    }

    /// Reads every epoch after `state`'s last through the epoch of `slot`.
    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        state: &AnonymousRingState,
        slot: u64,
    ) -> Result<AnonymousRingScan, ClientError> {
        let open = tag_epoch(slot);
        let mut scan = Scan {
            sync: self,
            state: state.clone(),
            ring_id: ring_id_field(state.ring.as_array())?,
            epochs: state
                .scanned_epoch
                .map_or(state.creation_epoch, |epoch| epoch.saturating_add(1))
                ..=open,
            decrypted: DecryptionResult::default(),
            notes: Vec::new(),
            anchors: Vec::new(),
            transactions: Vec::new(),
            tagged: HashSet::new(),
            opened: HashSet::new(),
            spends: HashSet::new(),
        };
        let mut reads = IndexerReads::configured(indexer, self.config);
        scan.streams(&mut reads).await?;
        // The change frontier starts from every note found, deposits included.
        scan.deposits(&mut reads).await?;
        scan.change(&mut reads).await?;
        let Scan {
            mut state,
            decrypted,
            notes,
            anchors,
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
        Ok(AnonymousRingScan {
            state,
            decrypted,
            notes,
            anchors,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    Inbox,
    Pair,
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
            StreamKind::Pair => AnonymousStream::Pair {
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

struct Streams {
    inboxes: Vec<(u32, InboxKey)>,
    pairs: Vec<(ReceivedAnchor, PairKey)>,
}

impl Streams {
    fn derive<K: ShieldedKeys + ?Sized>(
        scan: &Scan<'_, '_, K>,
        addresses: &[u32],
        anchors: &[ReceivedAnchor],
    ) -> Result<Self, ClientError> {
        let mut inboxes = Vec::with_capacity(addresses.len());
        if !addresses.is_empty() {
            let keys = scan
                .sync
                .keys
                .ring_address_keys(&scan.state.ring, addresses)?;
            check_count(keys.len(), addresses.len())?;
            for (index, key) in addresses.iter().zip(keys) {
                inboxes.push((*index, InboxKey::derive(&scan.ring_id, key.as_bytes())?));
            }
        }
        let pairs = anchors
            .iter()
            .map(|anchor| Ok((*anchor, PairKey::from_bytes(anchor.pair_key)?)))
            .collect::<Result<_, ClientError>>()?;
        Ok(Self { inboxes, pairs })
    }

    fn len(&self) -> usize {
        self.inboxes.len() + self.pairs.len()
    }

    fn sites(&self, epochs: &[u64]) -> Result<HashMap<[u8; 32], TagSite>, ClientError> {
        let mut sites = HashMap::new();
        for &epoch in epochs {
            for (address_index, inbox) in &self.inboxes {
                for index in TagIndex::all() {
                    let site = TagSite {
                        address_index: *address_index,
                        epoch,
                        index,
                        kind: StreamKind::Inbox,
                    };
                    sites.insert(inbox.tag(epoch, index)?.field(), site);
                }
            }
            for (anchor, pair) in &self.pairs {
                if epoch < anchor.epoch || epoch - anchor.epoch >= K_PAIR_EPOCHS {
                    continue;
                }
                for index in TagIndex::all() {
                    let site = TagSite {
                        address_index: anchor.address_index,
                        epoch,
                        index,
                        kind: StreamKind::Pair,
                    };
                    sites.insert(pair.tag(epoch, index)?.field(), site);
                }
            }
        }
        Ok(sites)
    }
}

struct Scan<'s, 'a, K: ?Sized> {
    sync: &'s AnonymousRingSync<'a, K>,
    state: AnonymousRingState,
    ring_id: [u8; 32],
    epochs: core::ops::RangeInclusive<u64>,
    decrypted: DecryptionResult,
    notes: Vec<AnonymousRingNote>,
    anchors: Vec<ReceivedAnchor>,
    transactions: Vec<ShieldedTransaction>,
    tagged: HashSet<(Signature, Option<u16>)>,
    /// A later round's stream still opens its own slots of a transaction read before.
    opened: HashSet<(Signature, Option<u16>, u32)>,
    /// Spends, a tagged transaction that spends a note still carries change.
    spends: HashSet<(Signature, Option<u16>)>,
}

impl<K: ShieldedKeys + ?Sized> Scan<'_, '_, K> {
    /// Rounds repeat until one adds no address or anchor, new streams read over every epoch.
    async fn streams<I: AsyncRpc + ?Sized>(
        &mut self,
        reads: &mut IndexerReads<'_, I>,
    ) -> Result<(), ClientError> {
        let mut read_addresses = BTreeSet::new();
        let mut read_anchors = HashSet::new();
        loop {
            let addresses: Vec<u32> = (0..self.state.address_window())
                .filter(|index| !read_addresses.contains(index))
                .collect();
            let anchors: Vec<ReceivedAnchor> = self
                .state
                .received
                .iter()
                .filter(|anchor| !read_anchors.contains(&anchor.pair_key))
                .copied()
                .collect();
            if addresses.is_empty() && anchors.is_empty() {
                return Ok(());
            }
            let streams = Streams::derive(self, &addresses, &anchors)?;
            read_addresses.extend(addresses);
            read_anchors.extend(anchors.iter().map(|anchor| anchor.pair_key));
            let per_chunk = (TAGS_PER_ROUND / (usize::from(J_INBOX) * streams.len().max(1))).max(1);
            let epochs: Vec<u64> = self.epochs.clone().collect();
            for chunk in epochs.chunks(per_chunk) {
                let sites = streams.sites(chunk)?;
                if sites.is_empty() {
                    continue;
                }
                let tags: Vec<[u8; 32]> = sites.keys().copied().collect();
                let transactions = reads.transactions(&tags).await?;
                self.open_streams(&sites, &transactions)?;
                self.transactions
                    .extend(fresh(&mut self.tagged, transactions));
            }
        }
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
                // Only an anonymous body earns a secret, any address holder publishes under its tags.
                if slot
                    .encrypted_body(EncryptedScheme::RingAnonymous)
                    .is_none()
                {
                    continue;
                }
                let output_index = slot_index(position)?;
                if !self
                    .opened
                    .insert((tx.tx_signature, tx.event_index, output_index))
                {
                    continue;
                }
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
            self.notes.push(AnonymousRingNote {
                utxo_hash: find.utxo_hash,
                stream: site.stream(),
            });
            if site.kind == StreamKind::Pair {
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
            let anchor = ReceivedAnchor {
                address_index: site.address_index,
                pair_key,
                epoch: site.epoch,
                asset: find.asset_address,
                amount: find.amount,
            };
            self.state.received.push(anchor);
            self.anchors.push(anchor);
        }
        Ok(())
    }

    async fn change<I: AsyncRpc + ?Sized>(
        &mut self,
        reads: &mut IndexerReads<'_, I>,
    ) -> Result<(), ClientError> {
        let change_key = self.sync.keys.ring_change_key(&self.state.ring)?;
        let viewing_pubkey = self.sync.keys.address()?.viewing_pubkey;
        let mut queried: HashSet<[u8; 32]> = HashSet::new();
        let mut frontier: Vec<[u8; 32]> = self
            .sync
            .known_nullifiers
            .iter()
            .chain(self.decrypted.utxos.iter().map(|utxo| &utxo.nullifier))
            .copied()
            .collect();
        loop {
            frontier.retain(|nullifier| queried.insert(*nullifier));
            if frontier.is_empty() {
                return Ok(());
            }
            let spends = fresh(&mut self.spends, reads.spends(&frontier).await?);
            let before: HashSet<[u8; 32]> = self
                .decrypted
                .utxos
                .iter()
                .map(|utxo| utxo.nullifier)
                .collect();
            self.open_change(&spends, &change_key, viewing_pubkey)?;
            self.open_merges(&spends)?;
            self.transactions.extend(spends);
            frontier = self
                .decrypted
                .utxos
                .iter()
                .map(|utxo| utxo.nullifier)
                .filter(|nullifier| !before.contains(nullifier))
                .collect();
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
                let agreement = tx_key.ecdh(change_key).map_err(TransactionError::from)?;
                for (position, slot) in tx.output_slots.iter().enumerate() {
                    if slot
                        .encrypted_body(EncryptedScheme::RingAnonymous)
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
        let finds = self.decrypted.extend_ring_delivered(
            self.sync.keys,
            self.sync.assets,
            spends,
            &candidates,
        )?;
        for find in finds {
            self.notes.push(AnonymousRingNote {
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
            self.notes.extend(
                merge
                    .output_slots
                    .iter()
                    .map(|slot| slot.output_context.hash)
                    .filter(|hash| held.contains(hash))
                    .map(|utxo_hash| AnonymousRingNote {
                        utxo_hash,
                        stream: AnonymousStream::Merge { first_nullifier },
                    }),
            );
        }
        Ok(())
    }

    async fn deposits<I: AsyncRpc + ?Sized>(
        &mut self,
        reads: &mut IndexerReads<'_, I>,
    ) -> Result<(), ClientError> {
        loop {
            let start = self.state.deposit_next;
            let counters: Vec<u64> = indices(start).collect();
            let tags = self.sync.keys.sender_view_tags(&counters)?;
            check_count(tags.len(), counters.len())?;
            let window = TagWindow::new(start, tags);
            let deposits = reads.deposits(&window.tags()).await?;
            let Some(&highest) = window.occupied(&deposits).last() else {
                return Ok(());
            };
            let deposits = self.unwrap_deposits(deposits)?;
            self.decrypted
                .extend(self.sync.keys, &deposits, self.sync.assets)?;
            self.state.deposit_next = highest.saturating_add(1);
        }
    }

    /// The ring's framing taken off its deposits, other rings' deposits left as published.
    fn unwrap_deposits(
        &self,
        deposits: Vec<ShieldedTransaction>,
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let mut unwrapped = Vec::with_capacity(deposits.len());
        for mut tx in deposits {
            let framing = tx.output_slots.iter_mut().try_for_each(|slot| {
                slot.unwrap_ring_deposit(&self.state.ring, self.sync.deposit_payload)
            });
            match framing {
                Ok(()) => unwrapped.push(tx),
                Err(error @ TransactionError::Serialize(_)) => return Err(error.into()),
                // A depositor's malformed framing occupies its tag and opens to nothing.
                Err(_) => {}
            }
        }
        Ok(unwrapped)
    }
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

/// The recipient's ciphertext inside an audited deposit's capsule, `None` without a capsule.
pub fn audit_capsule_payload(bytes: &[u8]) -> Result<Option<&[u8]>, TransactionError> {
    RingDepositAuditCapsule::parse(bytes)
        .map(|capsule| capsule.map(|capsule| capsule.recipient_ciphertext))
        .map_err(|error| TransactionError::Deserialize(error.to_string()))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentStream {
    Inbox,
    /// Anchored on the sender's live first contact to the address.
    Pair(SentFirstContact),
}

/// The tag a payment publishes in the epoch its proof binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentTag {
    pub stream: PaymentStream,
    pub epoch: u64,
    pub index: TagIndex,
    pub tag: RingTag,
}

/// One transaction's payment tags in one epoch, at most one of them pair-anchored.
#[must_use]
pub struct TagAllocation<'a, I: ?Sized> {
    indexer: &'a I,
    state: &'a AnonymousRingState,
    epoch: u64,
    config: Option<IndexerRpcConfig>,
    taken: HashSet<RingTag>,
    paired: bool,
}

impl<'a, I: AsyncRpc + ?Sized> TagAllocation<'a, I> {
    /// `state` is the sender's, its first contacts anchor pair payments.
    pub fn new(indexer: &'a I, state: &'a AnonymousRingState, epoch: u64) -> Self {
        Self {
            indexer,
            state,
            epoch,
            config: None,
            taken: HashSet::new(),
            paired: false,
        }
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// The pair stream of an admitted live first contact, else the inbox stream until it fills.
    pub async fn allocate(&mut self, address: &RingAddress) -> Result<PaymentTag, ClientError> {
        if address.ring_program_id != self.state.ring {
            return Err(ClientError::ForeignRingAddress {
                address_ring: address.ring_program_id,
                ring: self.state.ring,
            });
        }
        let recipient = address.recipient.viewing_pubkey;
        let contact = self
            .state
            .first_contact(&recipient, self.epoch)
            .filter(|contact| {
                !self.paired && address.pairing.admits(&contact.asset, contact.amount)
            });
        if let Some(contact) = contact.copied() {
            let pair = PairKey::derive(&SlotSecret::new(contact.slot_secret)?)?;
            if let Some((index, tag)) = self
                .lowest_free(|epoch, index| pair.tag(epoch, index))
                .await?
            {
                self.paired = true;
                return Ok(self.take(PaymentStream::Pair(contact), index, tag));
            }
        }
        let inbox = InboxKey::derive(
            &ring_id_field(self.state.ring.as_array())?,
            recipient.as_bytes(),
        )?;
        match self
            .lowest_free(|epoch, index| inbox.tag(epoch, index))
            .await?
        {
            Some((index, tag)) => Ok(self.take(PaymentStream::Inbox, index, tag)),
            None => Err(ClientError::InboxStreamFull { epoch: self.epoch }),
        }
    }

    fn take(&mut self, stream: PaymentStream, index: TagIndex, tag: RingTag) -> PaymentTag {
        self.taken.insert(tag);
        PaymentTag {
            stream,
            epoch: self.epoch,
            index,
            tag,
        }
    }

    /// The lowest index of the epoch whose tag no output publishes and no earlier payment took.
    async fn lowest_free(
        &self,
        tag_at: impl Fn(u64, TagIndex) -> Result<RingTag, zolana_hasher::HasherError>,
    ) -> Result<Option<(TagIndex, RingTag)>, ClientError> {
        let stream = TagIndex::all()
            .map(|index| Ok((index, tag_at(self.epoch, index)?)))
            .collect::<Result<Vec<_>, ClientError>>()?;
        let positions: HashMap<[u8; 32], TagIndex> = stream
            .iter()
            .map(|(index, tag)| (tag.field(), *index))
            .collect();
        let tags: Vec<[u8; 32]> = positions.keys().copied().collect();
        let used = occupied(
            &positions,
            &IndexerReads::configured(self.indexer, self.config)
                .transactions(&tags)
                .await?,
        );
        Ok(stream
            .into_iter()
            .find(|(index, tag)| !used.contains(index) && !self.taken.contains(tag)))
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
                    asset: anchor.asset.to_string(),
                    amount: anchor.amount.to_string(),
                })
                .collect(),
            sent: self
                .sent
                .iter()
                .map(|contact| ContactJson {
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
                })
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

    /// Another version fails with [`ClientError::AnonymousRingStateVersion`], a rescan rebuilds it.
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
        restored.received = state
            .received
            .iter()
            .map(|anchor| {
                Ok(ReceivedAnchor {
                    address_index: anchor.address_index,
                    pair_key: bytes("pairKey", &anchor.pair_key)?,
                    epoch: anchor.epoch,
                    asset: address(&anchor.asset)?,
                    amount: amount(&anchor.amount)?,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        restored.sent = state
            .sent
            .iter()
            .map(|contact| {
                Ok(SentFirstContact {
                    recipient: X25519Pubkey::from_bytes(bytes("recipient", &contact.recipient)?)?,
                    tree_id: contact.tree_id,
                    leaf_index: contact.leaf_index,
                    utxo_hash: bytes("utxoHash", &contact.utxo_hash)?,
                    slot_secret: bytes("slotSecret", &contact.slot_secret)?,
                    first_nullifier: bytes("firstNullifier", &contact.first_nullifier)?,
                    slot_index: contact.slot_index,
                    epoch: contact.epoch,
                    index: TagIndex::new(contact.index)?,
                    asset: address(&contact.asset)?,
                    amount: amount(&contact.amount)?,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        restored.deposit_next = state.deposit_next;
        for decoys in state.decoys {
            let leaves = decoys
                .leaves
                .iter()
                .map(|leaf| {
                    Ok(DecoyLeaf {
                        leaf_index: leaf.leaf_index,
                        hash: bytes("hash", &leaf.hash)?,
                    })
                })
                .collect::<Result<BTreeSet<_>, ClientError>>()?;
            restored
                .decoys
                .insert(decoys.tree_id, leaves.into_iter().collect());
        }
        Ok(restored)
    }
}

/// Names the field alone, its text may be a slot secret or a pair key.
fn bytes<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ClientError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
        .ok_or_else(|| ClientError::AnonymousRingState(format!("{field} is not {N} hex bytes")))
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
