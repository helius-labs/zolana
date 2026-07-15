use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    constants::{BLINDING_LEN, INFO_NULLIFIER},
    error::KeypairError,
    hash::{fe_right_align, poseidon},
    signing_key::SigningKey,
};

#[derive(Clone)]
pub struct NullifierKey {
    secret: Zeroizing<[u8; BLINDING_LEN]>,
}

impl AsRef<NullifierKey> for NullifierKey {
    fn as_ref(&self) -> &NullifierKey {
        self
    }
}

impl NullifierKey {
    pub fn new() -> Self {
        let mut secret = Zeroizing::new([0u8; BLINDING_LEN]);
        while secret.iter().all(|byte| *byte == 0) {
            OsRng.fill_bytes(secret.as_mut_slice());
        }
        Self { secret }
    }

    pub fn from_signing_key(signing_key: &SigningKey) -> Result<Self, KeypairError> {
        Self::from_signing_secret_key_bytes(signing_key.secret_bytes().as_slice())
    }

    pub fn from_signing_secret_key_bytes(ikm: &[u8]) -> Result<Self, KeypairError> {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut secret = Zeroizing::new([0u8; BLINDING_LEN]);
        hk.expand(INFO_NULLIFIER, secret.as_mut_slice())
            .map_err(|_| KeypairError::Hkdf)?;
        Ok(Self { secret })
    }

    pub fn from_secret(secret: [u8; BLINDING_LEN]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
        }
    }

    pub fn secret(&self) -> &[u8; BLINDING_LEN] {
        &self.secret
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; BLINDING_LEN]> {
        Zeroizing::new(*self.secret)
    }

    pub fn pubkey(&self) -> Result<[u8; 32], KeypairError> {
        let secret_fe = fe_right_align(self.secret.as_slice())?;
        poseidon(&[&secret_fe])
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], KeypairError> {
        let blinding_fe = fe_right_align(blinding)?;
        let secret_fe = fe_right_align(self.secret.as_slice())?;
        poseidon(&[utxo_hash, &blinding_fe, &secret_fe])
    }
}

impl Default for NullifierKey {
    fn default() -> Self {
        Self::new()
    }
}
