//! The privacy roles of one shielded wallet, exposed as the operations the
//! protocol needs of them and nothing more.
//!
//! No method returns a long-lived secret, and every method takes a batch, so a
//! remote holder answers a sync or a spend in one round trip per method.
//!
//! `decrypt` returns the transfer cipher's output rather than the ECDH shared
//! point. The view root is itself an ECDH with a fixed point and ECDH is
//! linear, so a chosen-point oracle over the viewing key would leak every
//! per-transaction key the wallet has used; keystream results do not compose
//! that way. The cipher is unauthenticated, so a ciphertext addressed to
//! another wallet decrypts to noise rather than failing, and the caller detects
//! that by the commitment.
//!
//! The nullifier secret is consumed, rather than derived from, in exactly one
//! place: proving. That capability lives on the client layer, next to the
//! witness types that need it, and is deliberately absent here.

use zolana_keypair::{
    shielded::{ShieldedAddress, ShieldedKeypair},
    viewing_key::Salt,
    NullifierKey, P256Pubkey, ViewingKey,
};

use crate::{
    error::TransactionError,
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_private_tx_blinding,
    },
};

/// Which cipher opened a slot. A ring deposit publishes one ciphertext and no
/// slot index; every other rail is a per-slot UTXO ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptLabel {
    Utxo,
    RingDeposit,
}

#[derive(Clone, Copy, Debug)]
pub struct DecryptRequest<'a> {
    pub ciphertext: &'a [u8],
    /// Which of the wallet's viewing keys opens this slot. A retired key still
    /// opens what was sent to it before the rotation.
    pub viewing_pubkey: P256Pubkey,
    pub tx_viewing_pubkey: P256Pubkey,
    pub salt: Salt,
    /// Zero for a ring deposit.
    pub slot_index: u32,
    pub label: DecryptLabel,
}

/// Every value the protocol derives from the nullifier secret. `Nullifier`
/// spends a UTXO; the merge variants produce a merge's padded-slot nullifiers,
/// its output blinding, and its private-transaction blinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveRequest {
    Nullifier {
        utxo_hash: [u8; 32],
        blinding: [u8; 32],
    },
    MergeDummyNullifier {
        first_nullifier: [u8; 32],
        slot_index: u8,
    },
    MergeOutputBlinding {
        first_nullifier: [u8; 32],
    },
    MergePrivateTxBlinding {
        first_nullifier: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionKeyRequest {
    pub viewing_pubkey: P256Pubkey,
    pub first_nullifier: [u8; 32],
}

pub trait ShieldedKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError>;

    /// Every viewing key held, the current one first. A sync opens under each.
    fn viewing_public_keys(&self) -> Vec<P256Pubkey>;

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError>;

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError>;

    /// Per-transaction viewing keys, one per request.
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError>;
}

/// In-process keys: the counterpart of a remote holder, answering the same
/// operations from viewing keys and a nullifier key held here. Carries every
/// viewing key the wallet has had, so outputs sent before a rotation still
/// open.
#[derive(Clone)]
pub struct LocalShieldedKeys {
    address: ShieldedAddress,
    viewing: Vec<ViewingKey>,
    nullifier: NullifierKey,
}

impl LocalShieldedKeys {
    /// `viewing` lists the current key first and retired keys after it.
    pub fn new(
        address: ShieldedAddress,
        viewing: Vec<ViewingKey>,
        nullifier: NullifierKey,
    ) -> Result<Self, TransactionError> {
        if !viewing
            .iter()
            .any(|key| key.pubkey() == address.viewing_pubkey)
        {
            return Err(TransactionError::AuthorityViewingKeyMismatch);
        }
        Ok(Self {
            address,
            viewing,
            nullifier,
        })
    }

    /// Copies the keypair's roles; the keypair stays the caller's.
    pub fn from_keypair(keypair: &ShieldedKeypair) -> Result<Self, TransactionError> {
        Self::new(
            keypair.shielded_address()?,
            vec![keypair.viewing_key.clone()],
            keypair.nullifier_key.clone(),
        )
    }

    fn viewing_key(&self, pubkey: &P256Pubkey) -> Result<&ViewingKey, TransactionError> {
        self.viewing
            .iter()
            .find(|key| &key.pubkey() == pubkey)
            .ok_or(TransactionError::UnknownViewingKey)
    }
}

impl ShieldedKeys for LocalShieldedKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.address)
    }

    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        self.viewing.iter().map(|key| key.pubkey()).collect()
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        requests
            .iter()
            .map(|request| {
                let viewing = self.viewing_key(&request.viewing_pubkey)?;
                let plaintext = match request.label {
                    DecryptLabel::Utxo => viewing.decrypt_utxo(
                        request.ciphertext,
                        &request.tx_viewing_pubkey,
                        request.salt,
                        request.slot_index,
                    ),
                    DecryptLabel::RingDeposit => viewing.decrypt_ring_deposit(
                        request.ciphertext,
                        &request.tx_viewing_pubkey,
                        request.salt,
                    ),
                }?;
                Ok(plaintext)
            })
            .collect()
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        requests
            .iter()
            .map(|request| match request {
                DeriveRequest::Nullifier {
                    utxo_hash,
                    blinding,
                } => Ok(self.nullifier.nullifier(utxo_hash, blinding)?),
                DeriveRequest::MergeDummyNullifier {
                    first_nullifier,
                    slot_index,
                } => merge_dummy_nullifier(&self.nullifier, first_nullifier, *slot_index),
                DeriveRequest::MergeOutputBlinding { first_nullifier } => {
                    merge_output_blinding(&self.nullifier, first_nullifier)
                }
                DeriveRequest::MergePrivateTxBlinding { first_nullifier } => {
                    merge_private_tx_blinding(&self.nullifier, first_nullifier)
                }
            })
            .collect()
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        requests
            .iter()
            .map(|request| {
                let viewing = self.viewing_key(&request.viewing_pubkey)?;
                Ok(viewing.get_transaction_viewing_key(&request.first_nullifier)?)
            })
            .collect()
    }
}

/// A software keypair answers the same operations directly, which is what the
/// tests and the local examples use.
impl ShieldedKeys for ShieldedKeypair {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.shielded_address()?)
    }

    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        vec![self.viewing_pubkey()]
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        LocalShieldedKeys::from_keypair(self)?.decrypt(requests)
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        LocalShieldedKeys::from_keypair(self)?.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        LocalShieldedKeys::from_keypair(self)?.transaction_keys(requests)
    }
}
