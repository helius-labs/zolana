use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
};

use solana_address::Address;
use solana_signature::Signature;
use zolana_keypair::{shielded::ShieldedAddress, viewing_key::ViewTag, P256Pubkey};

use crate::{
    error::TransactionError, instructions::transact::OutputContext, utxo::Utxo, AssetRegistry,
};

pub const DEFAULT_TAG_WINDOW: u64 = 64;
pub(crate) const SENDER_HISTORY_ROW_BASE: u64 = 1 << 63;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransactionId {
    pub signature: String,
    pub slot: u64,
    /// Stable row discriminator within the transaction. For received outputs this
    /// is the UTXO leaf index when available; sender-side aggregate rows use a
    /// high local row index range.
    pub index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateTransactionKind {
    Deposit,
    PrivateTransfer,
    PublicWithdrawal,
    Split,
    Merge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateTransactionDirection {
    Inbound,
    Outbound,
    SelfTransfer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateTransactionStatus {
    Confirmed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransaction {
    pub id: PrivateTransactionId,
    pub kind: PrivateTransactionKind,
    pub direction: PrivateTransactionDirection,
    pub status: PrivateTransactionStatus,
    pub asset: Address,
    pub amount: u64,
    pub counterparty_viewing_pubkey: Option<P256Pubkey>,
}

pub struct ViewingKeyEntry {
    pub viewing_pubkey: P256Pubkey,
    pub created_at: i64,
    pub tx_count: u64,
    pub request_count: u64,
    pub known_senders: HashMap<P256Pubkey, u64>,
    pub known_recipients: HashMap<P256Pubkey, u64>,
}

impl ViewingKeyEntry {
    pub fn new(viewing_pubkey: P256Pubkey, created_at: i64) -> Self {
        Self {
            viewing_pubkey,
            created_at,
            tx_count: 0,
            request_count: 0,
            known_senders: HashMap::new(),
            known_recipients: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    pub output_context: OutputContext,
    pub nullifier: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub spent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: u64,
    pub mint: Address,
    pub amount: u64,
    pub utxos: Vec<Utxo>,
}

/// Spendable default-ring balances.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balances {
    pub assets: Vec<AssetBalance>,
}

/// Holdings bound to one ring, never selectable by the default spend path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingBalance {
    pub ring_program_id: Address,
    pub assets: Vec<AssetBalance>,
}

impl Balances {
    pub fn get_balance(&self, mint: Address) -> Option<&AssetBalance> {
        self.assets.iter().find(|balance| balance.mint == mint)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    MinAmount(u64),
}

impl Filter {
    fn matches(&self, utxo: &Utxo) -> bool {
        match self {
            Filter::MinAmount(min) => utxo.amount >= *min,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub stored_utxos: usize,
    pub unparsed_transactions: usize,
    pub undecryptable_candidates: usize,
    /// Compact asset ids that failed to decode because the wallet's registry
    /// did not know them (SPL assets registered after the registry was built).
    /// The client sync layer uses this to lazily backfill the registry from
    /// chain and retry; it stays empty when every id is known.
    pub unknown_asset_ids: BTreeSet<u64>,
}

/// One transaction's place in the total order every rings stream shares.
///
/// Ordered by `(slot, signature)`, matching the indexer's pagination. Record a
/// position only once every row of that transaction has been applied, a resume
/// returns rows strictly after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChainPosition {
    pub slot: u64,
    pub signature: Signature,
}

impl Ord for ChainPosition {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.slot, self.signature.as_ref()).cmp(&(other.slot, other.signature.as_ref()))
    }
}

impl PartialOrd for ChainPosition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One key on one indexer stream. `ViewTag` is `[u8; 32]`, so the variant is
/// what stops a tag being read as a nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CursorStream {
    /// Shielded transactions matched by output view tag.
    Tags(ViewTag),
    /// Shielded transactions matched by spent nullifier.
    Nullifiers([u8; 32]),
    /// Encrypted UTXOs, which proofless deposits are read from.
    Proofless(ViewTag),
}

impl CursorStream {
    /// The tag or nullifier, for building the query.
    pub fn value(self) -> [u8; 32] {
        match self {
            Self::Tags(value) | Self::Nullifiers(value) | Self::Proofless(value) => value,
        }
    }
}

pub struct Wallet {
    /// Public wallet identity. All secret key material is supplied by a
    /// `WalletAuthority` when cryptographic work is required.
    pub identity: ShieldedAddress,
    /// Asset-id ↔ mint translation config for this wallet's session. Built once
    /// before the wallet and immutable afterward; the build and sync paths read
    /// it to encode/decode UTXO asset ids.
    pub registry: AssetRegistry,
    pub viewing_key_history: Vec<ViewingKeyEntry>,
    pub utxos: Vec<WalletUtxo>,
    pub transactions: Vec<PrivateTransaction>,
    /// Every input nullifier ever observed across synced transactions. Kept
    /// permanently so a UTXO discovered after its spend was seen still marks
    /// spent.
    pub nullifiers: HashSet<[u8; 32]>,
    pub last_synced: i64,
    /// Per key, the position everything matching it has been seen through.
    /// Streams advance independently. Nullifier entries die with their spend.
    pub cursors: HashMap<CursorStream, ChainPosition>,
}

impl Wallet {
    pub fn new(
        identity: ShieldedAddress,
        registry: AssetRegistry,
    ) -> Result<Self, TransactionError> {
        let viewing_pubkey = identity.viewing_pubkey;
        Ok(Self {
            identity,
            registry,
            viewing_key_history: vec![ViewingKeyEntry::new(viewing_pubkey, 0)],
            utxos: Vec::new(),
            transactions: Vec::new(),
            nullifiers: HashSet::new(),
            last_synced: 0,
            cursors: HashMap::new(),
        })
    }

    pub(crate) fn ensure_viewing_key_entries(
        &mut self,
        viewing_pubkeys: impl IntoIterator<Item = P256Pubkey>,
    ) {
        for viewing_pubkey in viewing_pubkeys {
            if self
                .viewing_key_history
                .iter()
                .all(|entry| entry.viewing_pubkey != viewing_pubkey)
            {
                self.viewing_key_history
                    .push(ViewingKeyEntry::new(viewing_pubkey, 0));
            }
        }
    }

    /// Every viewing key this wallet has been given, current and rotated-out.
    ///
    /// Seeded from the identity and extended by [`Self::ensure_viewing_key_entries`]
    /// on each sync, so it also holds keys a later scan's material omits. A scan
    /// snapshots this before it borrows the wallet mutably; a transfer addressed
    /// to any of these keys is addressed to this wallet.
    pub(crate) fn self_viewing_pubkeys(&self) -> HashSet<P256Pubkey> {
        self.viewing_key_history
            .iter()
            .map(|entry| entry.viewing_pubkey)
            .collect()
    }

    pub fn private_transactions(&self) -> &[PrivateTransaction] {
        &self.transactions
    }

    pub fn get_private_transactions(&self) -> Vec<PrivateTransaction> {
        self.transactions.clone()
    }

    pub(super) fn unspent(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.utxos.iter().filter(|u| !u.spent)
    }

    /// The spendable default-ring balance of one mint.
    pub fn balance(
        &self,
        mint: Address,
        filter: Option<Filter>,
    ) -> Result<AssetBalance, TransactionError> {
        let mut balance = AssetBalance {
            asset_id: self.registry.asset_id(&mint)?,
            mint,
            amount: 0,
            utxos: Vec::new(),
        };
        for wallet_utxo in self.unspent() {
            if wallet_utxo.utxo.asset != mint || wallet_utxo.utxo.ring_program_id.is_some() {
                continue;
            }
            if let Some(filter) = &filter {
                if !filter.matches(&wallet_utxo.utxo) {
                    continue;
                }
            }
            balance.amount = balance.amount.saturating_add(wallet_utxo.utxo.amount);
            balance.utxos.push(wallet_utxo.utxo.clone());
        }
        Ok(balance)
    }

    /// Spendable default-ring balances, ring-bound notes appear in
    /// [`Self::ring_balances`].
    pub fn balances(&self, skip_utxos: bool) -> Result<Vec<AssetBalance>, TransactionError> {
        self.asset_balances(skip_utxos, |entry| entry.utxo.ring_program_id.is_none())
    }

    pub fn ring_balances(&self, skip_utxos: bool) -> Result<Vec<RingBalance>, TransactionError> {
        let rings: BTreeSet<Address> = self
            .unspent()
            .filter_map(|entry| entry.utxo.ring_program_id)
            .collect();
        rings
            .into_iter()
            .map(|ring| {
                Ok(RingBalance {
                    ring_program_id: ring,
                    assets: self.asset_balances(skip_utxos, |entry| {
                        entry.utxo.ring_program_id == Some(ring)
                    })?,
                })
            })
            .collect()
    }

    fn asset_balances(
        &self,
        skip_utxos: bool,
        eligible: impl Fn(&WalletUtxo) -> bool,
    ) -> Result<Vec<AssetBalance>, TransactionError> {
        let mut by_mint: HashMap<Address, AssetBalance> = HashMap::new();
        for wallet_utxo in self.unspent() {
            if !eligible(wallet_utxo) {
                continue;
            }
            let balance = match by_mint.entry(wallet_utxo.utxo.asset) {
                Entry::Occupied(occupied) => occupied.into_mut(),
                Entry::Vacant(vacant) => vacant.insert(AssetBalance {
                    asset_id: self.registry.asset_id(&wallet_utxo.utxo.asset)?,
                    mint: wallet_utxo.utxo.asset,
                    amount: 0,
                    utxos: Vec::new(),
                }),
            };
            balance.amount = balance.amount.saturating_add(wallet_utxo.utxo.amount);
            if !skip_utxos {
                balance.utxos.push(wallet_utxo.utxo.clone());
            }
        }
        let mut balances: Vec<AssetBalance> = by_mint.into_values().collect();
        balances.sort_by_key(|b| b.asset_id);
        Ok(balances)
    }
}
