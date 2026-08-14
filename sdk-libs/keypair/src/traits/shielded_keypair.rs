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
/// Custody boundary: only the signing key can be hardware-resident — the
/// signing methods are fallible for that reason, and the nullifier and viewing
/// secrets are derivable from the device-produced seed alone
/// ([`crate::SigningKey::derivation_seed`]).
/// Both secrets stay host-side by design: both are private proof inputs, so
/// `nullifier_key()` returning the raw key is part of the minimal surface.
/// Construction is intentionally excluded, and so is signing-key ECDH: its
/// only consumer is role derivation at bootstrap, which every backend covers
/// through its own seed derivation.
pub trait ShieldedKeypairTrait {
    // --- identity ---

    fn signing_pubkey(&self) -> PublicKey;

    fn viewing_pubkey(&self) -> P256Pubkey;

    /// The signing curve / scheme of this keypair (P-256 shielded owner vs
    /// Ed25519 Solana-only owner), which selects the transfer rail.
    fn curve(&self) -> Curve;

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError>;

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError>;

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError>;

    // --- signing ---

    /// The scheme's native message signature: ed25519 over the raw bytes
    /// (RFC 8032), P256 as ECDSA over `SHA-256(message)` normalized to low-S,
    /// matching Solana's secp256r1 precompile. PDA owners cannot sign.
    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError>;

    /// ECDSA over a caller-supplied digest, the proof path. P-256 rail only;
    /// ed25519 owners sign digest bytes with [`Self::sign_message`].
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeypairError>;

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

    fn curve(&self) -> Curve {
        self.curve()
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

    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        self.sign_message(message)
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        self.sign_hash(hash)
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
