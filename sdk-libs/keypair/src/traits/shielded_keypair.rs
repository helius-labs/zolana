use crate::{
    error::KeypairError,
    nullifier_key::NullifierKey,
    pubkey::{Curve, P256Pubkey, PublicKey},
    shielded::{CompressedShieldedAddress, ShieldedAddress, ShieldedKeypair},
};

/// The keypair-level operations a shielded wallet needs that are *not* covered by
/// [`super::view_key::ViewingKeyTrait`] — signing identity, address derivation,
/// spend signing, and nullifier derivation. View-tag derivation and UTXO
/// encryption/decryption live on `ViewingKeyTrait`; a backend exposes both.
///
/// Custody boundary: only the signing key can be hardware-resident — `sign` is
/// fallible for that reason, and the nullifier and viewing secrets are
/// derivable from the device-produced seed alone
/// ([`crate::SigningKey::derivation_seed`]).
/// Both secrets stay host-side by design: both are private proof inputs, so
/// `nullifier_key()` returning the raw key is part of the minimal surface.
/// Construction is intentionally excluded.
pub trait ShieldedKeypairTrait {
    // --- identity ---

    fn signing_pubkey(&self) -> PublicKey;

    fn viewing_pubkey(&self) -> P256Pubkey;

    /// The signing curve / scheme of this keypair (P-256 shielded owner vs
    /// Ed25519 Solana-only owner), which selects the transfer rail.
    fn curve(&self) -> Result<Curve, KeypairError>;

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError>;

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError>;

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError>;

    // --- signing ---

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError>;

    // --- nullifiers ---

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError>;

    /// The owner's nullifier key, used to build spendable inputs.
    fn nullifier_key(&self) -> NullifierKey;

    fn nullifier_pubkey(&self) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key().pubkey()
    }
}

/// Forwards to the inherent `ShieldedKeypair` methods. Inherent methods win
/// method resolution over trait methods of the same name, so `self.foo()` calls
/// the concrete impl, not the trait method being defined.
impl ShieldedKeypairTrait for ShieldedKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_pubkey()
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_pubkey()
    }

    fn curve(&self) -> Result<Curve, KeypairError> {
        Ok(self.signing_key.curve())
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        self.shielded_address()
    }

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        self.owner_hash()
    }

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        self.compressed_address()
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError> {
        self.sign(msg)
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError> {
        self.nullifier(utxo_hash, blinding)
    }

    fn nullifier_key(&self) -> NullifierKey {
        self.nullifier_key.clone()
    }
}
