//! Shielded identities owned by a program-derived address
//! (`docs/shielded_pda_design.md`). A PDA is off the Ed25519 curve and holds
//! no private state, so the identity is rooted in an ECDH exchange between
//! viewing keys: both roles expand from that one shared secret, bound to the
//! PDA. Spending needs both the owning program's `invoke_signed` and the
//! nullifier secret; neither alone suffices.

use solana_address::Address;
use zeroize::Zeroizing;

use crate::{
    derivation::{p_pda, PdaRoleExpansion},
    error::KeypairError,
    hash::owner_hash,
    nullifier_key::NullifierKey,
    pubkey::{Curve, P256Pubkey, PublicKey},
    shielded::{CompressedShieldedAddress, ShieldedAddress},
    traits::ShieldedKeypairTrait,
    viewing_key::ViewingKey,
};

/// Not a `ShieldedKeypair`: it holds no signing secret, so that state is
/// unrepresentable rather than checked at run time.
#[derive(Clone)]
pub struct ShieldedPda {
    pda: Address,
    nullifier_key: NullifierKey,
    viewing_key: ViewingKey,
}

impl AsRef<NullifierKey> for ShieldedPda {
    fn as_ref(&self) -> &NullifierKey {
        &self.nullifier_key
    }
}

impl ShieldedPda {
    /// Derives both roles from `ECDH(own, counterparty)`, so either
    /// participant reconstructs the identity from its own viewing key and the
    /// counterparty's viewing public key; nothing is transported. A sole
    /// holder passes its own viewing public key as the counterparty.
    pub fn from_key_exchange(
        pda: Address,
        own: &ViewingKey,
        counterparty: &P256Pubkey,
    ) -> Result<Self, KeypairError> {
        let shared = Zeroizing::new(own.ecdh(counterparty)?);
        let expansion = PdaRoleExpansion::new(&shared, pda.to_bytes());
        Ok(Self {
            pda,
            nullifier_key: expansion.nullifier_key()?,
            viewing_key: expansion.viewing_key()?,
        })
    }

    /// Derives both roles from the holder's viewing key alone via
    /// `ECDH(own, P_pda)`, a committed point with unknown discrete log, so the
    /// identity exists before any counterparty does and its `nullifier_pk` can
    /// be published at account-creation time. The holder set is the same as
    /// the sole-holder exchange; only the holder of `own` derives it.
    pub fn from_viewing_key(pda: Address, own: &ViewingKey) -> Result<Self, KeypairError> {
        let shared = Zeroizing::new(own.ecdh_raw(&p_pda())?);
        let expansion = PdaRoleExpansion::new(&shared, pda.to_bytes());
        Ok(Self {
            pda,
            nullifier_key: expansion.nullifier_key()?,
            viewing_key: expansion.viewing_key()?,
        })
    }

    /// Supplied roles, for the flows the exchange cannot express: three or
    /// more parties that must each build spend proofs, or a protocol that
    /// fixes the values itself. A PDA has no signing key, so nothing can
    /// re-derive a supplied role.
    pub fn with_viewing_key(
        pda: Address,
        nullifier_key: NullifierKey,
        viewing_key: ViewingKey,
    ) -> Self {
        Self {
            pda,
            nullifier_key,
            viewing_key,
        }
    }

    pub fn pda(&self) -> &Address {
        &self.pda
    }

    pub fn signing_pubkey(&self) -> PublicKey {
        PublicKey::from_pda(&self.pda)
    }

    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
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

    /// The published half of the nullifier role: a PDA identity publishes this
    /// value (in the governing account or the registry) so verifiers can bind
    /// the owner hash without holding the secret.
    pub fn nullifier_pubkey(&self) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key.pubkey()
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

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key.nullifier(utxo_hash, blinding)
    }
}

impl ShieldedKeypairTrait for ShieldedPda {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_pubkey()
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_pubkey()
    }

    fn curve(&self) -> Curve {
        Curve::Pda
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

    fn sign_message(&self, _message: &[u8]) -> Result<[u8; 64], KeypairError> {
        Err(KeypairError::PdaCannotSign)
    }

    fn sign_hash(&self, _hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        Err(KeypairError::PdaCannotSign)
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

// Forwards to the identity's derived viewing key, so encryption and view-tag
// derivation need no special case.
crate::forward_viewing_key_trait!(ShieldedPda => viewing_key);
