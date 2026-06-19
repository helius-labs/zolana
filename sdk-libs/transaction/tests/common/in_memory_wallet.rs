use std::ops::{Deref, DerefMut};

use zolana_interface::event::DepositView;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{P256Pubkey, ShieldedKeypair};
use zolana_transaction::wallet::{SyncReport, SyncTransaction, Wallet, WalletKeyProvider};
use zolana_transaction::{AssetRegistry, TransactionError};

struct KeypairWalletKeyProvider<'a>(&'a ShieldedKeypair);

impl WalletKeyProvider for KeypairWalletKeyProvider<'_> {
    fn signing_pubkey(&self) -> zolana_keypair::PublicKey {
        self.0.signing_pubkey()
    }

    fn nullifier_pubkey(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self.0.nullifier_key.pubkey()?)
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.0.viewing_pubkey()
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], TransactionError> {
        Ok(self.0.nullifier_key.nullifier(utxo_hash, blinding)?)
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.0.recipient_bootstrap_view_tag()
    }

    fn get_sender_view_tag(&self, index: u64) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_sender_view_tag(index)
    }

    fn get_recipient_request_view_tag(
        &self,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_recipient_request_view_tag(index)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_send_shared_view_tag(counterparty, index)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_recipient_shared_view_tag(counterparty, index)
    }

    fn transaction_viewing_pubkey(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<P256Pubkey, TransactionError> {
        Ok(self
            .0
            .get_transaction_viewing_key(first_nullifier)?
            .pubkey())
    }

    fn encrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        recipient: &P256Pubkey,
        plaintext: &[u8],
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        Ok(self
            .0
            .get_transaction_viewing_key(first_nullifier)?
            .encrypt_slot(recipient, plaintext, salt, slot)?)
    }

    fn decrypt_root_slot(
        &self,
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        Ok(self
            .0
            .viewing_key
            .decrypt_utxo(ciphertext, peer, salt, slot)?)
    }

    fn decrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        Ok(self
            .0
            .get_transaction_viewing_key(first_nullifier)?
            .decrypt_slot_ephemeral(peer, ciphertext, salt, slot)?)
    }

    fn owner_hash(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self.0.owner_hash()?)
    }

    fn derive_proofless_blinding(
        &self,
        salt: &[u8; zolana_keypair::constants::SALT_LEN],
    ) -> Result<[u8; BLINDING_LEN], TransactionError> {
        Ok(self.0.viewing_key.derive_proofless_blinding(salt)?)
    }
}

pub struct InMemoryWallet {
    pub keypair: ShieldedKeypair,
    pub wallet: Wallet,
}

impl InMemoryWallet {
    pub fn new(keypair: ShieldedKeypair) -> Result<Self, TransactionError> {
        let wallet = Wallet::new(
            keypair.signing_pubkey(),
            keypair.nullifier_key.pubkey()?,
            keypair.viewing_pubkey(),
        );
        Ok(Self { keypair, wallet })
    }

    pub fn sync(
        &mut self,
        transactions: &[SyncTransaction],
        proofless_deposits: &[DepositView],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.wallet.sync(
            &KeypairWalletKeyProvider(&self.keypair),
            transactions,
            proofless_deposits,
            assets,
            synced_at,
            window,
        )
    }

    #[cfg(feature = "parallel")]
    pub fn sync_parallel(
        &mut self,
        transactions: &[SyncTransaction],
        _proofless_deposits: &[DepositView],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.wallet.sync_parallel(
            &KeypairWalletKeyProvider(&self.keypair),
            transactions,
            assets,
            synced_at,
            window,
        )
    }
}

impl Deref for InMemoryWallet {
    type Target = Wallet;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for InMemoryWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
