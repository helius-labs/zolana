use crate::{
    constants::{BLINDING_LEN, P256_PUBKEY_LEN, PUBLIC_KEY_LEN, SALT_LEN},
    error::KeypairError,
    hash::owner_hash,
    nullifier_key::NullifierKey,
    pubkey::{P256Pubkey, PublicKey},
    seed::wallet_seed_from_ed25519,
    signing_key::SigningKey,
    viewing_key::ViewingKey,
};

pub const SHIELDED_ADDRESS_LEN: usize = PUBLIC_KEY_LEN + 32 + P256_PUBKEY_LEN;

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

    pub fn to_bytes(self) -> [u8; SHIELDED_ADDRESS_LEN] {
        let mut bytes = [0u8; SHIELDED_ADDRESS_LEN];
        bytes[..PUBLIC_KEY_LEN].copy_from_slice(self.signing_pubkey.as_bytes());
        bytes[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 32].copy_from_slice(&self.nullifier_pubkey);
        bytes[PUBLIC_KEY_LEN + 32..].copy_from_slice(self.viewing_pubkey.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; SHIELDED_ADDRESS_LEN]) -> Result<Self, KeypairError> {
        let signing_pubkey = PublicKey::from_bytes(
            bytes[..PUBLIC_KEY_LEN]
                .try_into()
                .expect("shielded signing key slice has fixed length"),
        )?;
        let nullifier_pubkey = bytes[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 32]
            .try_into()
            .expect("shielded nullifier key slice has fixed length");
        let viewing_pubkey = P256Pubkey::from_bytes(
            bytes[PUBLIC_KEY_LEN + 32..]
                .try_into()
                .expect("shielded viewing key slice has fixed length"),
        )?;
        let address = Self {
            signing_pubkey,
            nullifier_pubkey,
            viewing_pubkey,
        };
        address.owner_hash()?;
        Ok(address)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompressedShieldedAddress {
    pub owner_hash: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
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

    /// A Solana-only owner's shielded keypair: the ed25519 secret is the
    /// signing key; the nullifier key derives from it directly and the viewing
    /// key through the [`wallet_seed_from_ed25519`] bridge at the standard
    /// SLIP-0010 viewing path, so the whole identity is recoverable from the
    /// Solana keypair alone.
    pub fn from_ed25519(signing_secret: &[u8; 32]) -> Result<Self, KeypairError> {
        let signing_key = SigningKey::from_ed25519(signing_secret);
        let nullifier_key = NullifierKey::from_signing_secret_key_bytes(signing_secret)?;
        let wallet_seed = wallet_seed_from_ed25519(signing_secret)?;
        let viewing_key = ViewingKey::from_seed(&wallet_seed, 0)?;
        Ok(Self {
            signing_key,
            nullifier_key,
            viewing_key,
        })
    }

    /// Reconstruct the shielded wallet from a Solana keypair (its Ed25519 secret
    /// is the signing key; nullifier and viewing keys derive from it — see
    /// [`Self::from_ed25519`]). The Solana keypair alone recovers the wallet.
    pub fn from_solana_keypair(keypair: &solana_keypair::Keypair) -> Result<Self, KeypairError> {
        Self::from_ed25519(keypair.secret_bytes())
    }

    pub fn signing_pubkey(&self) -> PublicKey {
        self.signing_key.pubkey()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_keypair_is_deterministic_from_the_solana_secret() {
        let secret = [7u8; 32];
        let first = ShieldedKeypair::from_ed25519(&secret).unwrap();
        let second = ShieldedKeypair::from_ed25519(&secret).unwrap();

        assert_eq!(
            first.shielded_address().unwrap(),
            second.shielded_address().unwrap()
        );

        let other = ShieldedKeypair::from_ed25519(&[8u8; 32]).unwrap();
        assert_ne!(
            first.viewing_pubkey().as_bytes(),
            other.viewing_pubkey().as_bytes()
        );
        assert_ne!(
            first.nullifier_key.pubkey().unwrap(),
            other.nullifier_key.pubkey().unwrap()
        );
    }

    #[test]
    fn ed25519_viewing_key_derivation_is_stable() {
        let keypair = ShieldedKeypair::from_ed25519(&[7u8; 32]).unwrap();

        assert_eq!(
            hex::encode(keypair.viewing_pubkey().as_bytes()),
            "029186d9897fc6b2877220a3aca216eb24162ac6ebb6cbcc710b7e9a491548383f"
        );
    }
}
