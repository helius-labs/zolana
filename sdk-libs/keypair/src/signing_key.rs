use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as EcdsaSig, SigningKey as EcdsaSigningKey, VerifyingKey};
use p256::SecretKey;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::KeypairError;
use crate::pubkey::{P256Pubkey, PublicKey};

pub struct SigningKey {
    secret: SecretKey,
}

impl SigningKey {
    pub fn new() -> Self {
        Self {
            secret: SecretKey::random(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self { secret })
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.secret.to_bytes().as_slice());
        Zeroizing::new(out)
    }

    pub fn pubkey(&self) -> PublicKey {
        PublicKey::from_p256(&P256Pubkey::from_p256(&self.secret.public_key()))
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let signing = EcdsaSigningKey::from_bytes(&self.secret.to_bytes())
            .expect("valid scalar from a valid secret key");
        let sig: EcdsaSig = signing.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.to_bytes().as_slice());
        out
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let vk = VerifyingKey::from(self.secret.public_key());
        match EcdsaSig::from_slice(sig) {
            Ok(parsed) => vk.verify(msg, &parsed).is_ok(),
            Err(_) => false,
        }
    }
}

impl Default for SigningKey {
    fn default() -> Self {
        Self::new()
    }
}
