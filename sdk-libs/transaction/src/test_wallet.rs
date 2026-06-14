use std::ops::{Deref, DerefMut};

use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedKeypair};

use crate::asset::AssetRegistry;
use crate::error::TransactionError;
use crate::wallet::{AssetBalance, SyncReport, SyncTransaction, Wallet, WalletCrypto};

pub struct TestWallet {
    pub keypair: ShieldedKeypair,
    pub wallet: Wallet,
    pub private_wallet_created: bool,
    pub encrypted_state: Option<Vec<u8>>,
}

impl TestWallet {
    pub fn new(keypair: ShieldedKeypair) -> Result<Self, TransactionError> {
        let wallet = Wallet::new(
            keypair.signing_pubkey(),
            keypair.nullifier_key.pubkey()?,
            keypair.viewing_pubkey(),
        );
        Ok(Self {
            keypair,
            wallet,
            private_wallet_created: false,
            encrypted_state: None,
        })
    }

    pub fn sync(
        &mut self,
        transactions: &[SyncTransaction],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        struct Crypto<'a>(&'a ShieldedKeypair);
        impl WalletCrypto for Crypto<'_> {
            fn signing_pubkey(&self) -> PublicKey {
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

            fn get_sender_view_tag(
                &self,
                index: u64,
            ) -> Result<ViewTag, zolana_keypair::KeypairError> {
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
        }

        self.wallet.sync(
            &Crypto(&self.keypair),
            transactions,
            assets,
            synced_at,
            window,
        )
    }

    #[cfg(feature = "parallel")]
    pub fn sync_parallel(
        &mut self,
        transactions: &[SyncTransaction],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.sync(transactions, assets, synced_at, window)
    }

    pub fn balances(
        &self,
        assets: &AssetRegistry,
        skip_utxos: bool,
    ) -> Result<Vec<AssetBalance>, TransactionError> {
        self.wallet.balances(assets, skip_utxos)
    }
}

impl WalletCrypto for TestWallet {
    fn signing_pubkey(&self) -> PublicKey {
        self.keypair.signing_pubkey()
    }

    fn nullifier_pubkey(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self.keypair.nullifier_key.pubkey()?)
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.keypair.viewing_pubkey()
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], TransactionError> {
        Ok(self.keypair.nullifier_key.nullifier(utxo_hash, blinding)?)
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.keypair.recipient_bootstrap_view_tag()
    }

    fn get_sender_view_tag(&self, index: u64) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.keypair.get_sender_view_tag(index)
    }

    fn get_recipient_request_view_tag(
        &self,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.keypair.get_recipient_request_view_tag(index)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.keypair.get_send_shared_view_tag(counterparty, index)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.keypair
            .get_recipient_shared_view_tag(counterparty, index)
    }

    fn transaction_viewing_pubkey(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<P256Pubkey, TransactionError> {
        Ok(self
            .keypair
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
            .keypair
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
            .keypair
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
            .keypair
            .get_transaction_viewing_key(first_nullifier)?
            .decrypt_slot_ephemeral(peer, ciphertext, salt, slot)?)
    }
}

impl Deref for TestWallet {
    type Target = Wallet;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for TestWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
