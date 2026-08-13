use zeroize::Zeroizing;

use crate::{
    constants::BLINDING_LEN,
    error::KeypairError,
    hash::{poseidon, right_align},
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
    pub(crate) fn from_zeroizing_secret(secret: Zeroizing<[u8; BLINDING_LEN]>) -> Self {
        Self { secret }
    }

    pub fn from_secret(secret: [u8; BLINDING_LEN]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
        }
    }

    pub fn secret(&self) -> Zeroizing<[u8; BLINDING_LEN]> {
        self.secret.clone()
    }

    pub fn pubkey(&self) -> Result<[u8; 32], KeypairError> {
        let secret_fe = right_align(&self.secret);
        poseidon(&[&secret_fe])
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError> {
        let secret_fe = right_align(&self.secret);
        poseidon(&[utxo_hash, blinding, &secret_fe])
    }
}
