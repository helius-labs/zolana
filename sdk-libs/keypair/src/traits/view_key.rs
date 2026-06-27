use crate::{
    error::KeypairError,
    pubkey::P256Pubkey,
    shielded::ShieldedKeypair,
    viewing_key::{Salt, ViewTag, ViewingKey},
};

/// The viewing-key operations a shielded wallet needs — view-tag derivation,
/// per-slot UTXO encryption/decryption, and transaction-viewing-key derivation —
/// abstracted so the wallet and transfer layers can run over any backend (the
/// in-memory [`ViewingKey`], or an HSM / embedded viewing key) rather than a
/// concrete type.
///
/// DRAFT: mirrors the current [`ViewingKey`] operational surface. Constructors
/// and `secret_bytes` (raw key export) are intentionally excluded — a backend
/// keeps the secret material and exposes only operations over it.
pub trait ViewingKeyTrait {
    // --- identity / key agreement ---

    fn pubkey(&self) -> P256Pubkey;

    /// ECDH with `counterparty`, returning the shared point's x-coordinate.
    fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError>;

    // --- view-tag derivation ---

    fn get_sender_view_tag(&self, tx_count: u64) -> Result<ViewTag, KeypairError>;

    fn get_recipient_request_view_tag(&self, request_count: u64) -> Result<ViewTag, KeypairError>;

    fn get_merge_view_tag(&self, merge_count: u64) -> Result<ViewTag, KeypairError>;

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError>;

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError>;

    fn recipient_bootstrap_view_tag(&self) -> ViewTag;

    fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError>;

    // --- per-slot UTXO encryption ---

    fn encrypt_slot(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError>;

    // --- per-slot UTXO decryption ---

    fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError>;

    fn decrypt_slot_ephemeral(
        &self,
        recipient_pubkey: &P256Pubkey,
        ciphertext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError>;

    // encryption with poseidon kdf keypair
    fn encrypt_verifiable(
        &self,
        user_viewing_pk: &P256Pubkey,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, P256Pubkey), KeypairError>;

    // decryption with poseidon kdf keypair
    fn decrypt_verifiable(
        &self,
        tx_viewing_pubkey: &P256Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeypairError>;
}

/// Forwards to the inherent `ViewingKey` methods. Inherent methods win method
/// resolution over trait methods of the same name, so `self.foo()` calls the
/// concrete impl, not the trait method being defined.
impl ViewingKeyTrait for ViewingKey {
    fn pubkey(&self) -> P256Pubkey {
        self.pubkey()
    }

    fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        self.ecdh(counterparty)
    }

    fn get_sender_view_tag(&self, tx_count: u64) -> Result<ViewTag, KeypairError> {
        self.get_sender_view_tag(tx_count)
    }

    fn get_recipient_request_view_tag(&self, request_count: u64) -> Result<ViewTag, KeypairError> {
        self.get_recipient_request_view_tag(request_count)
    }

    fn get_merge_view_tag(&self, merge_count: u64) -> Result<ViewTag, KeypairError> {
        self.get_merge_view_tag(merge_count)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.get_send_shared_view_tag(counterparty, i)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.get_recipient_shared_view_tag(counterparty, i)
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.recipient_bootstrap_view_tag()
    }

    fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError> {
        self.get_transaction_viewing_key(first_nullifier)
    }

    fn encrypt_slot(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.encrypt_slot(recipient_pubkey, plaintext, salt, slot_index)
    }

    fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.decrypt_utxo(ciphertext, tx_viewing_pubkey, salt, slot_index)
    }

    fn decrypt_slot_ephemeral(
        &self,
        recipient_pubkey: &P256Pubkey,
        ciphertext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.decrypt_slot_ephemeral(recipient_pubkey, ciphertext, salt, slot_index)
    }

    fn encrypt_verifiable(
        &self,
        user_viewing_pk: &P256Pubkey,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, P256Pubkey), KeypairError> {
        self.encrypt_verifiable(user_viewing_pk, plaintext)
    }

    fn decrypt_verifiable(
        &self,
        tx_viewing_pubkey: &P256Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeypairError> {
        self.decrypt_verifiable(tx_viewing_pubkey, ciphertext)
    }
}

/// Forwards to the keypair's inner `viewing_key`, so a full [`ShieldedKeypair`]
/// can stand in wherever a viewing-key backend is required.
impl ViewingKeyTrait for ShieldedKeypair {
    fn pubkey(&self) -> P256Pubkey {
        self.viewing_key.pubkey()
    }

    fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        self.viewing_key.ecdh(counterparty)
    }

    fn get_sender_view_tag(&self, tx_count: u64) -> Result<ViewTag, KeypairError> {
        self.viewing_key.get_sender_view_tag(tx_count)
    }

    fn get_recipient_request_view_tag(&self, request_count: u64) -> Result<ViewTag, KeypairError> {
        self.viewing_key
            .get_recipient_request_view_tag(request_count)
    }

    fn get_merge_view_tag(&self, merge_count: u64) -> Result<ViewTag, KeypairError> {
        self.viewing_key.get_merge_view_tag(merge_count)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.viewing_key.get_send_shared_view_tag(counterparty, i)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.viewing_key
            .get_recipient_shared_view_tag(counterparty, i)
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.viewing_key.recipient_bootstrap_view_tag()
    }

    fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError> {
        self.viewing_key
            .get_transaction_viewing_key(first_nullifier)
    }

    fn encrypt_slot(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.viewing_key
            .encrypt_slot(recipient_pubkey, plaintext, salt, slot_index)
    }

    fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.viewing_key
            .decrypt_utxo(ciphertext, tx_viewing_pubkey, salt, slot_index)
    }

    fn decrypt_slot_ephemeral(
        &self,
        recipient_pubkey: &P256Pubkey,
        ciphertext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.viewing_key
            .decrypt_slot_ephemeral(recipient_pubkey, ciphertext, salt, slot_index)
    }

    fn encrypt_verifiable(
        &self,
        user_viewing_pk: &P256Pubkey,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, P256Pubkey), KeypairError> {
        self.viewing_key
            .encrypt_verifiable(user_viewing_pk, plaintext)
    }

    fn decrypt_verifiable(
        &self,
        tx_viewing_pubkey: &P256Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeypairError> {
        self.viewing_key
            .decrypt_verifiable(tx_viewing_pubkey, ciphertext)
    }
}
