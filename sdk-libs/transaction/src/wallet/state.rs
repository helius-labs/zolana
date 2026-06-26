use std::collections::{hash_map::Entry, HashMap, HashSet};

use solana_address::Address;
use zolana_keypair::{P256Pubkey, ShieldedKeypair, ViewingKey};

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
    pub key: ViewingKey,
    pub created_at: i64,
    pub tx_count: u64,
    pub request_count: u64,
    pub known_senders: HashMap<P256Pubkey, u64>,
    pub known_recipients: HashMap<P256Pubkey, u64>,
}

impl ViewingKeyEntry {
    pub fn new(key: ViewingKey, created_at: i64) -> Self {
        Self {
            key,
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
pub struct SyncReport {
    pub stored_utxos: usize,
    pub unparsed_transactions: usize,
    pub undecryptable_candidates: usize,
}

pub struct Wallet {
    pub keypair: ShieldedKeypair,
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
    pub fn new(keypair: ShieldedKeypair) -> Result<Self, TransactionError> {
        let key = ViewingKey::from_bytes(&keypair.viewing_key.secret_bytes())?;
        Ok(Self {
            keypair,
            viewing_key_history: vec![ViewingKeyEntry::new(key, 0)],
            utxos: Vec::new(),
            transactions: Vec::new(),
            nullifiers: HashSet::new(),
            last_synced: 0,
        })
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

    pub fn balances(
        &self,
        assets: &AssetRegistry,
        skip_utxos: bool,
    ) -> Result<Vec<AssetBalance>, TransactionError> {
        let mut by_mint: HashMap<Address, AssetBalance> = HashMap::new();
        for wallet_utxo in self.unspent() {
            let balance = match by_mint.entry(wallet_utxo.utxo.asset) {
                Entry::Occupied(occupied) => occupied.into_mut(),
                Entry::Vacant(vacant) => vacant.insert(AssetBalance {
                    asset_id: assets.asset_id(&wallet_utxo.utxo.asset)?,
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
