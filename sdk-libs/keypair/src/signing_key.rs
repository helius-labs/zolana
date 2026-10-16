use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as DalekSigningKey};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    derivation,
    error::KeypairError,
    pubkey::{Curve, PublicKey},
};

#[derive(Clone)]
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl SigningKey {
    /// Generates an Ed25519 owner and zeroizes the temporary secret bytes.
    pub fn new_ed25519() -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        Self::from_ed25519_bytes(&secret)
    }

    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: DalekSigningKey::from_bytes(bytes),
        }
    }

    pub fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.inner.as_bytes())
    }

    pub fn pubkey(&self) -> PublicKey {
        PublicKey::from_ed25519(self.inner.verifying_key().as_bytes())
    }

    /// Signs the message with RFC 8032 Ed25519. Derivation messages are refused
    /// because their signatures reveal the seed for the owner's private roles.
    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        Ok(self.inner.sign(message).to_bytes())
    }

    /// Derives private roles from the deterministic signature over the dedicated message.
    pub fn derivation_seed(&self) -> Result<Zeroizing<Vec<u8>>, KeypairError> {
        let message = derivation::ed25519_derivation_message(self.inner.verifying_key().as_bytes());
        Ok(Zeroizing::new(
            self.inner.sign(&message).to_bytes().to_vec(),
        ))
    }
}

impl From<&solana_keypair::Keypair> for SigningKey {
    fn from(keypair: &solana_keypair::Keypair) -> Self {
        Self::from_ed25519_bytes(keypair.secret_bytes())
    }
}
