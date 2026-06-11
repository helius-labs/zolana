use hkdf::Hkdf;
use sha2::Sha256;

use crate::constants::{BLINDING_LEN, INFO_NULLIFIER};
use crate::error::KeypairError;
use crate::hash::{fe_right_align, poseidon};
use crate::signing_key::SigningKey;

pub struct NullifierKey {
    secret: [u8; BLINDING_LEN],
}

impl NullifierKey {
    pub fn from_signing_key(signing_key: &SigningKey) -> Result<Self, KeypairError> {
        Self::from_signing_secret_key_bytes(signing_key.secret_bytes().as_slice())
    }

    pub fn from_signing_secret_key_bytes(ikm: &[u8]) -> Result<Self, KeypairError> {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut secret = [0u8; BLINDING_LEN];
        hk.expand(INFO_NULLIFIER, &mut secret)
            .map_err(|_| KeypairError::Hkdf)?;
        Ok(Self { secret })
    }

    pub fn from_secret(secret: [u8; BLINDING_LEN]) -> Self {
        Self { secret }
    }

    pub fn secret(&self) -> &[u8; BLINDING_LEN] {
        &self.secret
    }

    pub fn pubkey(&self) -> Result<[u8; 32], KeypairError> {
        let secret_fe = fe_right_align(&self.secret)?;
        poseidon(&[&secret_fe])
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], KeypairError> {
        let blinding_fe = fe_right_align(blinding)?;
        let secret_fe = fe_right_align(&self.secret)?;
        poseidon(&[utxo_hash, &blinding_fe, &secret_fe])
    }
}
