use crate::{
    constants::{BLINDING_LEN, SALT_LEN},
    error::KeypairError,
    hash::{owner_hash, pack33, poseidon},
    nullifier_key::NullifierKey,
    pubkey::{P256Pubkey, PublicKey},
    signing_key::SigningKey,
    viewing_key::ViewingKey,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldedAddress {
    pub signing_pubkey: PublicKey,
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

impl ShieldedAddress {
    pub fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        owner_hash(&self.signing_pubkey, &self.nullifier_pubkey)
    }

    pub fn solana_address(&self) -> Result<solana_address::Address, KeypairError> {
        Ok(solana_address::Address::new_from_array(
            self.signing_pubkey.as_ed25519()?,
        ))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompressedShieldedAddress {
    pub owner_hash: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

impl CompressedShieldedAddress {
    pub fn hash(&self) -> Result<[u8; 32], KeypairError> {
        let (lo, hi) = pack33(self.viewing_pubkey.as_bytes());
        poseidon(&[&self.owner_hash, &lo, &hi])
    }
}

impl TryFrom<&ShieldedAddress> for CompressedShieldedAddress {
    type Error = KeypairError;

    fn try_from(address: &ShieldedAddress) -> Result<Self, Self::Error> {
        Ok(Self {
            owner_hash: address.owner_hash()?,
            viewing_pubkey: address.viewing_pubkey,
        })
    }
}

#[derive(Clone)]
pub struct ShieldedKeypair {
    pub signing_key: SigningKey,
    pub nullifier_key: NullifierKey,
    pub viewing_key: ViewingKey,
}

impl AsRef<NullifierKey> for ShieldedKeypair {
    fn as_ref(&self) -> &NullifierKey {
        &self.nullifier_key
    }
}

impl ShieldedKeypair {
    pub fn from_keys(
        signing_key: SigningKey,
        viewing_key: ViewingKey,
    ) -> Result<Self, KeypairError> {
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

    pub fn new() -> Result<Self, KeypairError> {
        Self::from_keys(SigningKey::new(), ViewingKey::new())
    }

    pub fn from_ed25519(
        signing_secret: &[u8; 32],
        viewing_key: ViewingKey,
    ) -> Result<Self, KeypairError> {
        let signing_key = SigningKey::from_ed25519(signing_secret);
        let nullifier_key = NullifierKey::from_signing_secret_key_bytes(signing_secret)?;
        Ok(Self {
            signing_key,
            nullifier_key,
            viewing_key,
        })
    }

    pub fn from_solana_keypair(keypair: &solana_keypair::Keypair) -> Result<Self, KeypairError> {
        let signing_secret = keypair.secret_bytes();
        let viewing_key = ViewingKey::from_seed(signing_secret, 0)?;
        Self::from_ed25519(signing_secret, viewing_key)
    }

    pub fn signing_pubkey(&self) -> PublicKey {
        self.signing_key.pubkey()
    }

    pub fn to_solana_keypair(&self) -> Result<solana_keypair::Keypair, KeypairError> {
        if !self.signing_key.is_ed25519() {
            return Err(KeypairError::NotEd25519);
        }
        Ok(solana_keypair::Keypair::new_from_array(
            *self.signing_key.secret_bytes(),
        ))
    }

    pub fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_key.pubkey()
    }

    pub fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_pubkey(),
            nullifier_pubkey: self.nullifier_key.pubkey()?,
            viewing_pubkey: self.viewing_pubkey(),
        })
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        owner_hash(&self.signing_pubkey(), &self.nullifier_key.pubkey()?)
    }

    pub fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        Ok(CompressedShieldedAddress {
            owner_hash: self.owner_hash()?,
            viewing_pubkey: self.viewing_pubkey(),
        })
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg)
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key.nullifier(utxo_hash, blinding)
    }

    pub fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.viewing_key
            .decrypt_utxo(ciphertext, tx_viewing_pubkey, salt, slot_index)
    }

    pub fn decrypt_verifiable(
        &self,
        tx_viewing_pubkey: &P256Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeypairError> {
        self.viewing_key
            .decrypt_verifiable(tx_viewing_pubkey, ciphertext)
    }

    pub fn get_sender_view_tag(&self, tx_count: u64) -> Result<[u8; 32], KeypairError> {
        self.viewing_key.get_sender_view_tag(tx_count)
    }

    pub fn get_recipient_request_view_tag(
        &self,
        request_count: u64,
    ) -> Result<[u8; 32], KeypairError> {
        self.viewing_key
            .get_recipient_request_view_tag(request_count)
    }

    pub fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; 32], KeypairError> {
        self.viewing_key.get_send_shared_view_tag(counterparty, i)
    }

    pub fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; 32], KeypairError> {
        self.viewing_key
            .get_recipient_shared_view_tag(counterparty, i)
    }

    pub fn get_merge_view_tag(&self, merge_count: u64) -> Result<[u8; 32], KeypairError> {
        self.viewing_key.get_merge_view_tag(merge_count)
    }

    pub fn recipient_bootstrap_view_tag(&self) -> [u8; 32] {
        self.viewing_key.recipient_bootstrap_view_tag()
    }

    pub fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError> {
        self.viewing_key
            .get_transaction_viewing_key(first_nullifier)
    }
}
