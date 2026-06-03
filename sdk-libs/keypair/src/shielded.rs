use crate::constants::BLINDING_LEN;
use crate::error::Error;
use crate::hash::owner_hash;
use crate::nullifier_key::NullifierKey;
use crate::pubkey::{P256Pubkey, PublicKey};
use crate::signing_key::SigningKey;
use crate::viewing_key::ViewingKey;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldedAddress {
    pub signing_pubkey: PublicKey,
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

pub struct ShieldedKeypair {
    pub signing_key: SigningKey,
    pub nullifier_key: NullifierKey,
    pub viewing_key: ViewingKey,
}

impl ShieldedKeypair {
    pub fn from_keys(signing_key: SigningKey, viewing_key: ViewingKey) -> Result<Self, Error> {
        let nullifier_key = NullifierKey::from_signing_key(&signing_key)?;
        Ok(Self {
            signing_key,
            nullifier_key,
            viewing_key,
        })
    }

    pub fn from_parts(
        signing_key: SigningKey,
        nullifier_key: NullifierKey,
        viewing_key: ViewingKey,
    ) -> Self {
        Self {
            signing_key,
            nullifier_key,
            viewing_key,
        }
    }

    pub fn new() -> Result<Self, Error> {
        Self::from_keys(SigningKey::new_p256(), ViewingKey::new())
    }

    pub fn new_ed25519() -> Result<Self, Error> {
        Self::from_keys(SigningKey::new_ed25519(), ViewingKey::new())
    }

    pub fn signing_pubkey(&self) -> PublicKey {
        self.signing_key.signing_pubkey()
    }

    pub fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_key.viewing_pubkey()
    }

    pub fn nullifier_pubkey(&self) -> Result<[u8; 32], Error> {
        self.nullifier_key.nullifier_pubkey()
    }

    pub fn shielded_address(&self) -> Result<ShieldedAddress, Error> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_pubkey(),
            nullifier_pubkey: self.nullifier_pubkey()?,
            viewing_pubkey: self.viewing_pubkey(),
        })
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], Error> {
        owner_hash(&self.signing_pubkey(), &self.nullifier_pubkey()?)
    }

    pub fn compressed_address(&self) -> Result<([u8; 32], P256Pubkey), Error> {
        Ok((self.owner_hash()?, self.viewing_pubkey()))
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg)
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], Error> {
        self.nullifier_key.nullifier(utxo_hash, blinding)
    }

    pub fn encrypt(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.viewing_key.encrypt(recipient_pubkey, plaintext)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
    ) -> Result<Vec<u8>, Error> {
        self.viewing_key.decrypt(ciphertext, tx_viewing_pubkey)
    }

    pub fn get_sender_view_tag(&self, tx_count: u64) -> Result<[u8; 32], Error> {
        self.viewing_key.get_sender_view_tag(tx_count)
    }

    pub fn get_recipient_request_view_tag(&self, request_count: u64) -> Result<[u8; 32], Error> {
        self.viewing_key
            .get_recipient_request_view_tag(request_count)
    }

    pub fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; 32], Error> {
        self.viewing_key.get_send_shared_view_tag(counterparty, i)
    }

    pub fn get_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; 32], Error> {
        self.viewing_key.get_shared_view_tag(counterparty, i)
    }

    pub fn get_merge_view_tag(
        &self,
        merge_authority_pubkey: &[u8],
        merge_count: u64,
    ) -> Result<[u8; 32], Error> {
        self.viewing_key
            .get_merge_view_tag(merge_authority_pubkey, merge_count)
    }

    pub fn recipient_bootstrap_view_tag(&self) -> [u8; 32] {
        self.viewing_key.recipient_bootstrap_view_tag()
    }

    pub fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, Error> {
        self.viewing_key
            .get_transaction_viewing_key(first_nullifier)
    }
}
