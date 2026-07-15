use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};

use solana_address::Address;
use zolana_keypair::{shielded::ShieldedAddress, P256Pubkey};

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
    pub zone_data_hash: Option<[u8; 32]>,
    pub spent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: u64,
    pub mint: Address,
    pub amount: u64,
    pub utxos: Vec<Utxo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balances {
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
    /// True when sync exhausted its configured discovery rounds while each
    /// round was still finding new transactions. Callers must not treat this
    /// report as a complete wallet view until a later sync converges.
    pub discovery_truncated: bool,
    /// Compact asset ids that failed to decode because the wallet's registry
    /// did not know them (SPL assets registered after the registry was built).
    /// The client sync layer uses this to lazily backfill the registry from
    /// chain and retry; it stays empty when every id is known.
    pub unknown_asset_ids: BTreeSet<u64>,
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

    pub fn private_transactions(&self) -> &[PrivateTransaction] {
        &self.transactions
    }

    pub fn get_private_transactions(&self) -> Vec<PrivateTransaction> {
        self.transactions.clone()
    }

    pub(super) fn unspent(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.utxos.iter().filter(|u| !u.spent)
    }

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
            if wallet_utxo.utxo.asset != mint {
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

    pub fn balances(&self, skip_utxos: bool) -> Result<Vec<AssetBalance>, TransactionError> {
        let mut by_mint: HashMap<Address, AssetBalance> = HashMap::new();
        for wallet_utxo in self.unspent() {
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
