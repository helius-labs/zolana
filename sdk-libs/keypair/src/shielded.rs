use solana_signer::{Signer, SignerError};

use crate::{
    constants::SALT_LEN,
    derivation::{Rail, RoleExpansion},
    error::KeypairError,
    hash::{owner_hash, poseidon},
    nullifier_key::NullifierKey,
    pubkey::{Curve, P256Pubkey, PublicKey},
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
    pub fn for_pda(
        pda: &solana_address::Address,
        nullifier_pubkey: [u8; 32],
        viewing_pubkey: P256Pubkey,
    ) -> Self {
        Self {
            signing_pubkey: PublicKey::from_pda(pda),
            nullifier_pubkey,
            viewing_pubkey,
        }
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        owner_hash(&self.signing_pubkey, &self.nullifier_pubkey)
    }

    pub fn solana_address(&self) -> Result<solana_address::Address, KeypairError> {
        let bytes = match self.signing_pubkey.curve()? {
            Curve::Ed25519 => self.signing_pubkey.as_ed25519()?,
            Curve::Pda => self.signing_pubkey.as_pda()?,
            Curve::P256 => return Err(KeypairError::NoSolanaAddress),
        };
        Ok(solana_address::Address::new_from_array(bytes))
    }

    pub fn confidential_view_tag(&self) -> Result<[u8; 32], KeypairError> {
        self.signing_pubkey.confidential_view_tag()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompressedShieldedAddress {
    pub owner_hash: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

impl CompressedShieldedAddress {
    pub fn hash(&self) -> Result<[u8; 32], KeypairError> {
        let viewing_key_hash =
            zolana_hasher::primitives::hash_bytes(self.viewing_pubkey.as_bytes())?;
        poseidon(&[&self.owner_hash, &viewing_key_hash])
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
#[non_exhaustive]
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

impl Signer for ShieldedKeypair {
    fn try_pubkey(&self) -> Result<solana_address::Address, SignerError> {
        if self.signing_key.curve() != Curve::Ed25519 {
            return Err(KeypairError::NoSolanaAddress.into());
        }
        let bytes = self.signing_pubkey().as_ed25519()?;
        Ok(solana_address::Address::new_from_array(bytes))
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<solana_keypair::Signature, SignerError> {
        if self.signing_key.curve() != Curve::Ed25519 {
            return Err(KeypairError::NotEd25519.into());
        }
        Ok(solana_keypair::Signature::from(self.sign(message)?))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

impl ShieldedKeypair {
    /// A fresh random keypair on the P-256 rail: both role keys expand from
    /// `ECDH(signing_sk, P_derive)`.
    pub fn new_p256() -> Result<Self, KeypairError> {
        Self::from_keypair(SigningKey::new_p256())
    }

    /// A fresh random keypair on the ed25519 rail: both role keys expand from
    /// the deterministic signature over the derivation message, and the owner
    /// has a Solana address.
    pub fn new_ed25519() -> Result<Self, KeypairError> {
        Self::from_keypair(SigningKey::new_ed25519())
    }

    pub fn from_keypair<K>(keypair: K) -> Result<Self, KeypairError>
    where
        K: Into<SigningKey>,
    {
        let signing_key: SigningKey = keypair.into();
        let seed = signing_key.derivation_seed()?;
        let viewing_key =
            RoleExpansion::new(&seed, Rail::from_curve(signing_key.curve())?).viewing_key()?;
        Self::with_viewing_key(signing_key, viewing_key)
    }

    /// Same derivation as [`Self::from_keypair`] with a shared viewing key in
    /// place of the derived one; the nullifier key is still derived from the
    /// signing key, so no argument can detach it.
    pub fn with_viewing_key(
        signing_key: SigningKey,
        viewing_key: ViewingKey,
    ) -> Result<Self, KeypairError> {
        let seed = signing_key.derivation_seed()?;
        let expansion = RoleExpansion::new(&seed, Rail::from_curve(signing_key.curve())?);
        Ok(Self {
            signing_key,
            nullifier_key: expansion.nullifier_key()?,
            viewing_key,
        })
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

    // TODO: rename to sign message
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError> {
        self.signing_key.sign(msg)
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
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
