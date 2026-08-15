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
}

/// Implements [`ViewingKeyTrait`] for a type that owns a [`ViewingKey`], by
/// forwarding every method to the named field:
///
/// ```ignore
/// zolana_keypair::forward_viewing_key_trait!(MyBackend => viewing_key);
/// ```
///
/// Call sites inside this crate spell it `crate::forward_viewing_key_trait!`:
/// an exported macro is only in textual scope after its definition, and some
/// modules here are declared before this one. A doc comment cannot attach to
/// the invocation either, so the call sites explain themselves with `//`.
///
/// The trait is twelve methods and a host-side viewing key forwards all of
/// them identically, so writing it out is pure noise that can silently drift
/// between backends.
///
/// A blanket impl over an accessor trait would be the tidier-looking fix and is
/// the wrong tool: it would make it impossible for a downstream crate to
/// implement [`ViewingKeyTrait`] by hand, since coherence must assume that type
/// could pick up the accessor later. Hand-written impls are exactly what a
/// device-resident viewing key needs — one that performs ECDH in an HSM and can
/// never produce a `&ViewingKey` to forward to. A macro leaves that door open.
#[macro_export]
macro_rules! forward_viewing_key_trait {
    ($backend:ty => $field:ident) => {
        impl $crate::ViewingKeyTrait for $backend {
            fn pubkey(&self) -> $crate::P256Pubkey {
                self.$field.pubkey()
            }

            fn ecdh(
                &self,
                counterparty: &$crate::P256Pubkey,
            ) -> ::core::result::Result<[u8; 32], $crate::KeypairError> {
                self.$field.ecdh(counterparty)
            }

            fn get_sender_view_tag(
                &self,
                tx_count: u64,
            ) -> ::core::result::Result<$crate::viewing_key::ViewTag, $crate::KeypairError> {
                self.$field.get_sender_view_tag(tx_count)
            }

            fn get_recipient_request_view_tag(
                &self,
                request_count: u64,
            ) -> ::core::result::Result<$crate::viewing_key::ViewTag, $crate::KeypairError> {
                self.$field.get_recipient_request_view_tag(request_count)
            }

            fn get_send_shared_view_tag(
                &self,
                counterparty: &$crate::P256Pubkey,
                i: u64,
            ) -> ::core::result::Result<$crate::viewing_key::ViewTag, $crate::KeypairError> {
                self.$field.get_send_shared_view_tag(counterparty, i)
            }

            fn get_recipient_shared_view_tag(
                &self,
                counterparty: &$crate::P256Pubkey,
                i: u64,
            ) -> ::core::result::Result<$crate::viewing_key::ViewTag, $crate::KeypairError> {
                self.$field.get_recipient_shared_view_tag(counterparty, i)
            }

            fn recipient_bootstrap_view_tag(&self) -> $crate::viewing_key::ViewTag {
                self.$field.recipient_bootstrap_view_tag()
            }

            fn get_transaction_viewing_key(
                &self,
                first_nullifier: &[u8; 32],
            ) -> ::core::result::Result<$crate::ViewingKey, $crate::KeypairError> {
                self.$field.get_transaction_viewing_key(first_nullifier)
            }

            fn encrypt_slot(
                &self,
                recipient_pubkey: &$crate::P256Pubkey,
                plaintext: &[u8],
                salt: $crate::viewing_key::Salt,
                slot_index: u32,
            ) -> ::core::result::Result<::std::vec::Vec<u8>, $crate::KeypairError> {
                self.$field
                    .encrypt_slot(recipient_pubkey, plaintext, salt, slot_index)
            }

            fn decrypt_utxo(
                &self,
                ciphertext: &[u8],
                tx_viewing_pubkey: &$crate::P256Pubkey,
                salt: $crate::viewing_key::Salt,
                slot_index: u32,
            ) -> ::core::result::Result<::std::vec::Vec<u8>, $crate::KeypairError> {
                self.$field
                    .decrypt_utxo(ciphertext, tx_viewing_pubkey, salt, slot_index)
            }

            fn decrypt_slot_ephemeral(
                &self,
                recipient_pubkey: &$crate::P256Pubkey,
                ciphertext: &[u8],
                salt: $crate::viewing_key::Salt,
                slot_index: u32,
            ) -> ::core::result::Result<::std::vec::Vec<u8>, $crate::KeypairError> {
                self.$field
                    .decrypt_slot_ephemeral(recipient_pubkey, ciphertext, salt, slot_index)
            }
        }
    };
}

/// Forwards to the inherent `ViewingKey` methods. Inherent methods win method
/// resolution over trait methods of the same name, so `self.foo()` calls the
/// concrete impl, not the trait method being defined.
///
/// Not written with [`forward_viewing_key_trait!`]: this is the base case the
/// macro forwards *to*, and it has no field to name.
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
}

// Forwards to the keypair's inner `viewing_key`, so a full `ShieldedKeypair`
// can stand in wherever a viewing-key backend is required.
crate::forward_viewing_key_trait!(ShieldedKeypair => viewing_key);
