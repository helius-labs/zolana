use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zolana_interface::event::DepositView;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::wallet::SyncTransaction;
use zolana_transaction::{Address, AssetRegistry};

use crate::{
    DecryptionMode, PrivateTransaction, PrivateTransactionKind, PrivateWallet, PrivateWalletId,
    Result, TransactionDirection, TransactionStatus, WalletError,
};

pub struct SyncSnapshot {
    pub transactions: Vec<SyncTransaction>,
    pub proofless_deposits: Vec<DepositView>,
    pub assets: AssetRegistry,
}

pub trait PrivacyBackend: Send {
    fn reserve_wallet_id(&mut self, inbox: Address) -> Result<PrivateWalletId>;
    fn register_wallet(&mut self, wallet: PrivateWallet) -> Result<()>;
    fn set_decryption_mode(
        &mut self,
        wallet_id: PrivateWalletId,
        mode: DecryptionMode,
    ) -> Result<()>;
    fn resolve_wallet_by_inbox(&self, inbox: Address) -> Result<PrivateWallet>;
    fn fetch_sync_snapshot(&self) -> Result<SyncSnapshot>;
    fn asset_id_for_mint(&mut self, mint: Address) -> Result<u64>;
    fn unique_blinding(&mut self) -> [u8; BLINDING_LEN];
    fn record_private_transfer(
        &mut self,
        sender_wallet_id: PrivateWalletId,
        recipient_wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
        transaction: SyncTransaction,
    ) -> Result<String>;
    fn record_proofless_deposit(
        &mut self,
        wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
        deposit: DepositView,
    ) -> Result<String>;
    fn history(&self, wallet_id: PrivateWalletId, limit: usize) -> Result<Vec<PrivateTransaction>>;
}

#[derive(Clone)]
pub struct ProviderParts {
    pub next_wallet_id: u64,
    pub next_asset_id: u64,
    pub next_counter: u64,
    pub next_signature: u64,
    pub transactions: Vec<SyncTransaction>,
    pub proofless_deposits: Vec<DepositView>,
    pub assets: AssetRegistry,
}

#[derive(Default)]
struct InMemoryState {
    next_wallet_id: u64,
    next_asset_id: u64,
    next_counter: u64,
    next_signature: u64,
    wallets: HashMap<PrivateWalletId, PrivateWallet>,
    inboxes: HashMap<Address, PrivateWalletId>,
    transactions: Vec<SyncTransaction>,
    proofless_deposits: Vec<DepositView>,
    history: HashMap<PrivateWalletId, Vec<PrivateTransaction>>,
    assets: AssetRegistry,
}

impl InMemoryState {
    fn asset_id_for_mint(&mut self, mint: Address) -> Result<u64> {
        if let Ok(asset_id) = self.assets.asset_id(&mint) {
            return Ok(asset_id);
        }
        self.next_asset_id = self.next_asset_id.max(2);
        let asset_id = self.next_asset_id;
        self.next_asset_id += 1;
        self.assets.insert(asset_id, mint)?;
        Ok(asset_id)
    }

    fn unique_blinding(&mut self) -> [u8; BLINDING_LEN] {
        self.next_counter += 1;
        let mut out = [0u8; BLINDING_LEN];
        out[0] = 0x42;
        out[1..9].copy_from_slice(&self.next_counter.to_be_bytes());
        out
    }

    fn next_signature(&mut self) -> String {
        self.next_signature += 1;
        format!("mock-signature-{}", self.next_signature)
    }
}

#[derive(Clone)]
pub struct InMemoryPrivacyProvider {
    state: Arc<Mutex<InMemoryState>>,
}

impl Default for InMemoryPrivacyProvider {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(InMemoryState::default())),
        }
    }
}

impl InMemoryPrivacyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_parts(parts: ProviderParts) -> Self {
        let state = InMemoryState {
            next_wallet_id: parts.next_wallet_id,
            next_asset_id: parts.next_asset_id,
            next_counter: parts.next_counter,
            next_signature: parts.next_signature,
            wallets: HashMap::new(),
            inboxes: HashMap::new(),
            transactions: parts.transactions,
            proofless_deposits: parts.proofless_deposits,
            history: HashMap::new(),
            assets: parts.assets,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn export_parts(&self) -> Result<ProviderParts> {
        let state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        Ok(ProviderParts {
            next_wallet_id: state.next_wallet_id,
            next_asset_id: state.next_asset_id,
            next_counter: state.next_counter,
            next_signature: state.next_signature,
            transactions: state.transactions.clone(),
            proofless_deposits: state.proofless_deposits.clone(),
            assets: state.assets.clone(),
        })
    }
}

impl PrivacyBackend for InMemoryPrivacyProvider {
    fn reserve_wallet_id(&mut self, inbox: Address) -> Result<PrivateWalletId> {
        let mut state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        if state.inboxes.contains_key(&inbox) {
            return Err(WalletError::InboxAlreadyRegistered);
        }
        state.next_wallet_id += 1;
        Ok(PrivateWalletId(state.next_wallet_id))
    }

    fn register_wallet(&mut self, wallet: PrivateWallet) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        state.inboxes.insert(wallet.inbox, wallet.id);
        state.wallets.insert(wallet.id, wallet);
        Ok(())
    }

    fn set_decryption_mode(
        &mut self,
        wallet_id: PrivateWalletId,
        mode: DecryptionMode,
    ) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        let wallet = state
            .wallets
            .get_mut(&wallet_id)
            .ok_or(WalletError::PrivateWalletNotFound)?;
        wallet.decryption_mode = mode;
        Ok(())
    }

    fn resolve_wallet_by_inbox(&self, inbox: Address) -> Result<PrivateWallet> {
        let state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        let wallet_id = state
            .inboxes
            .get(&inbox)
            .copied()
            .ok_or(WalletError::RecipientPrivateWalletNotFound)?;
        state
            .wallets
            .get(&wallet_id)
            .cloned()
            .ok_or(WalletError::RecipientPrivateWalletNotFound)
    }

    fn fetch_sync_snapshot(&self) -> Result<SyncSnapshot> {
        let state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        Ok(SyncSnapshot {
            transactions: state.transactions.clone(),
            proofless_deposits: state.proofless_deposits.clone(),
            assets: state.assets.clone(),
        })
    }

    fn asset_id_for_mint(&mut self, mint: Address) -> Result<u64> {
        self.state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?
            .asset_id_for_mint(mint)
    }

    fn unique_blinding(&mut self) -> [u8; BLINDING_LEN] {
        self.state
            .lock()
            .expect("in-memory provider lock poisoned")
            .unique_blinding()
    }

    fn record_private_transfer(
        &mut self,
        sender_wallet_id: PrivateWalletId,
        recipient_wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
        transaction: SyncTransaction,
    ) -> Result<String> {
        let mut state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        state.transactions.push(transaction);
        let signature = state.next_signature();
        let slot = state.next_signature;
        state.history.entry(sender_wallet_id).or_default().insert(
            0,
            PrivateTransaction {
                kind: PrivateTransactionKind::PrivateTransfer,
                direction: TransactionDirection::Outbound,
                mint,
                amount,
                status: TransactionStatus::Confirmed,
                signature: Some(signature.clone()),
                slot: Some(slot),
            },
        );
        state
            .history
            .entry(recipient_wallet_id)
            .or_default()
            .insert(
                0,
                PrivateTransaction {
                    kind: PrivateTransactionKind::PrivateTransfer,
                    direction: TransactionDirection::Inbound,
                    mint,
                    amount,
                    status: TransactionStatus::Confirmed,
                    signature: Some(signature.clone()),
                    slot: Some(slot),
                },
            );
        Ok(signature)
    }

    fn record_proofless_deposit(
        &mut self,
        wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
        deposit: DepositView,
    ) -> Result<String> {
        let mut state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        state.proofless_deposits.push(deposit);
        let signature = state.next_signature();
        let slot = state.next_signature;
        state.history.entry(wallet_id).or_default().insert(
            0,
            PrivateTransaction {
                kind: PrivateTransactionKind::MockAirdrop,
                direction: TransactionDirection::Inbound,
                mint,
                amount,
                status: TransactionStatus::Confirmed,
                signature: Some(signature.clone()),
                slot: Some(slot),
            },
        );
        Ok(signature)
    }

    fn history(&self, wallet_id: PrivateWalletId, limit: usize) -> Result<Vec<PrivateTransaction>> {
        let state = self.state.lock().map_err(|_| WalletError::LockPoisoned)?;
        let mut history = state.history.get(&wallet_id).cloned().unwrap_or_default();
        if history.len() > limit {
            history.truncate(limit);
        }
        Ok(history)
    }
}

pub struct LocalnetBackend {
    inner: InMemoryPrivacyProvider,
    #[cfg(feature = "solana-rpc")]
    _solana: crate::solana_rpc::SolanaRpc,
    #[cfg(feature = "indexer-api")]
    _indexer: crate::indexer::ZolanaIndexer,
}

impl LocalnetBackend {
    #[cfg(all(feature = "solana-rpc", feature = "indexer-api"))]
    pub fn new(
        solana: crate::solana_rpc::SolanaRpc,
        indexer: crate::indexer::ZolanaIndexer,
    ) -> Self {
        Self {
            inner: InMemoryPrivacyProvider::new(),
            _solana: solana,
            _indexer: indexer,
        }
    }
}

impl PrivacyBackend for LocalnetBackend {
    fn reserve_wallet_id(&mut self, inbox: Address) -> Result<PrivateWalletId> {
        self.inner.reserve_wallet_id(inbox)
    }

    fn register_wallet(&mut self, wallet: PrivateWallet) -> Result<()> {
        self.inner.register_wallet(wallet)
    }

    fn set_decryption_mode(
        &mut self,
        wallet_id: PrivateWalletId,
        mode: DecryptionMode,
    ) -> Result<()> {
        self.inner.set_decryption_mode(wallet_id, mode)
    }

    fn resolve_wallet_by_inbox(&self, inbox: Address) -> Result<PrivateWallet> {
        self.inner.resolve_wallet_by_inbox(inbox)
    }

    fn fetch_sync_snapshot(&self) -> Result<SyncSnapshot> {
        self.inner.fetch_sync_snapshot()
    }

    fn asset_id_for_mint(&mut self, mint: Address) -> Result<u64> {
        self.inner.asset_id_for_mint(mint)
    }

    fn unique_blinding(&mut self) -> [u8; BLINDING_LEN] {
        self.inner.unique_blinding()
    }

    fn record_private_transfer(
        &mut self,
        sender_wallet_id: PrivateWalletId,
        recipient_wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
        transaction: SyncTransaction,
    ) -> Result<String> {
        self.inner.record_private_transfer(
            sender_wallet_id,
            recipient_wallet_id,
            mint,
            amount,
            transaction,
        )
    }

    fn record_proofless_deposit(
        &mut self,
        wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
        deposit: DepositView,
    ) -> Result<String> {
        self.inner
            .record_proofless_deposit(wallet_id, mint, amount, deposit)
    }

    fn history(&self, wallet_id: PrivateWalletId, limit: usize) -> Result<Vec<PrivateTransaction>> {
        self.inner.history(wallet_id, limit)
    }
}
