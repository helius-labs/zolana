//! The privacy roles of one shielded wallet, exposed as the operations the
//! protocol needs of them and nothing more.
//!
//! No method returns a long-lived secret, and every method takes a batch, so a
//! remote holder answers a sync or a spend in one round trip per method.
//!
//! `decrypt` returns the transfer cipher's output rather than the ECDH shared
//! point. The view root is HKDF-Extract over the clamped X25519 secret with
//! the salt `TSPP/view_root/x25519/v1`, so no ECDH query reaches it, but a
//! chosen-point oracle over the viewing key would still leak every
//! per-transaction key the wallet has used; keystream results do not compose
//! that way. The cipher is unauthenticated, so a ciphertext addressed to
//! another wallet decrypts to noise rather than failing, and the caller detects
//! that by the commitment.
//!
//! The nullifier secret is consumed, rather than derived from, in exactly one
//! place: proving. That capability lives on the client layer, next to the
//! witness types that need it, and is deliberately absent here.

use std::collections::{hash_map::Entry, HashMap};

use custom_ring_interface::ANONYMOUS_OUTPUT_PLAINTEXT_LEN;
use zolana_keypair::{
    shielded::{ShieldedAddress, ShieldedKeypair},
    viewing_key::{Salt, ViewTag},
    NullifierKey, ViewingKey, X25519Pubkey,
};

use crate::{
    error::TransactionError,
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_output_key, merge_private_tx_blinding,
    },
    serialization::ring_anonymous::RingAnonymousSlot,
};

/// Which cipher opened a slot. A ring deposit publishes one ciphertext and no
/// slot index; every other rail is a per-slot UTXO ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptLabel {
    Utxo,
    RingDeposit,
    /// The scheme-9 ciphertext after its scheme byte, opened under its slot stream.
    RingAnonymous,
}

#[derive(Clone, Copy, Debug)]
pub struct DecryptRequest<'a> {
    pub ciphertext: &'a [u8],
    /// Which of the wallet's viewing keys opens this slot. A retired key still
    /// opens what was sent to it before the rotation.
    pub viewing_pubkey: X25519Pubkey,
    pub tx_viewing_pubkey: X25519Pubkey,
    pub salt: Salt,
    /// Zero for a ring deposit.
    pub slot_index: u32,
    pub label: DecryptLabel,
}

/// Every value the protocol derives from the nullifier secret. `Nullifier`
/// spends a UTXO; the merge variants produce a merge's padded-slot nullifiers,
/// its output blinding, its private-transaction blinding, and the per-merge
/// key of its output ciphertext.
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
    MergeOutputKey {
        first_nullifier: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionKeyRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub first_nullifier: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RingTagRequest {
    Inbox {
        viewing_pubkey: X25519Pubkey,
        address_index: u32,
        j: u64,
    },
    Pair {
        viewing_pubkey: X25519Pubkey,
        counterparty: X25519Pubkey,
        k: u64,
    },
    Deposit {
        viewing_pubkey: X25519Pubkey,
        n: u64,
    },
    Change {
        viewing_pubkey: X25519Pubkey,
        first_nullifier: [u8; 32],
        slot: u8,
    },
}

impl RingTagRequest {
    pub fn viewing_pubkey(&self) -> X25519Pubkey {
        match *self {
            Self::Inbox { viewing_pubkey, .. }
            | Self::Pair { viewing_pubkey, .. }
            | Self::Deposit { viewing_pubkey, .. }
            | Self::Change { viewing_pubkey, .. } => viewing_pubkey,
        }
    }
}

pub trait ShieldedKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError>;

    /// Every viewing key held, the current one first. A sync opens under each.
    fn viewing_public_keys(&self) -> Vec<X25519Pubkey>;

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError>;

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError>;

    /// Per-transaction viewing keys, one per request.
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError>;

    fn ring_view_tags(&self, requests: &[RingTagRequest])
        -> Result<Vec<ViewTag>, TransactionError>;
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

    fn viewing_key(&self, pubkey: &X25519Pubkey) -> Result<&ViewingKey, TransactionError> {
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

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.viewing.iter().map(|key| key.pubkey()).collect()
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        let mut agreements: HashMap<(X25519Pubkey, X25519Pubkey), [u8; 32]> = HashMap::new();
        let mut plaintexts = Vec::with_capacity(requests.len());
        for request in requests {
            let viewing = self.viewing_key(&request.viewing_pubkey)?;
            let plaintext = match request.label {
                DecryptLabel::Utxo => viewing.decrypt_utxo(
                    request.ciphertext,
                    &request.tx_viewing_pubkey,
                    request.salt,
                    request.slot_index,
                )?,
                DecryptLabel::RingDeposit => viewing.decrypt_ring_deposit(
                    request.ciphertext,
                    &request.tx_viewing_pubkey,
                    request.salt,
                )?,
                DecryptLabel::RingAnonymous => {
                    let dh = match agreements
                        .entry((request.viewing_pubkey, request.tx_viewing_pubkey))
                    {
                        Entry::Occupied(known) => *known.get(),
                        Entry::Vacant(vacant) => {
                            *vacant.insert(viewing.ecdh(&request.tx_viewing_pubkey)?)
                        }
                    };
                    let mut body: [u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN] = request
                        .ciphertext
                        .try_into()
                        .map_err(|_| TransactionError::InvalidLength {
                            expected: ANONYMOUS_OUTPUT_PLAINTEXT_LEN,
                            actual: request.ciphertext.len(),
                        })?;
                    RingAnonymousSlot {
                        tx_viewing_pk: request.tx_viewing_pubkey,
                        recipient_pk: request.viewing_pubkey,
                        salt: request.salt,
                        slot: u8::try_from(request.slot_index)
                            .map_err(|_| TransactionError::TooManyOutputs)?,
                    }
                    .apply(&dh, &mut body)?;
                    body.to_vec()
                }
            };
            plaintexts.push(plaintext);
        }
        Ok(plaintexts)
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
                DeriveRequest::MergeOutputKey { first_nullifier } => {
                    merge_output_key(&self.nullifier, first_nullifier)
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

    fn ring_view_tags(
        &self,
        requests: &[RingTagRequest],
    ) -> Result<Vec<ViewTag>, TransactionError> {
        requests
            .iter()
            .map(|request| {
                let viewing = self.viewing_key(&request.viewing_pubkey())?;
                let tag = match *request {
                    RingTagRequest::Inbox {
                        address_index, j, ..
                    } => viewing.inbox_secret(address_index)?.view_tag(j),
                    RingTagRequest::Pair {
                        counterparty, k, ..
                    } => viewing.get_recipient_shared_view_tag(&counterparty, k),
                    RingTagRequest::Deposit { n, .. } => viewing.get_sender_view_tag(n),
                    RingTagRequest::Change {
                        first_nullifier,
                        slot,
                        ..
                    } => viewing.ring_change_view_tag(&first_nullifier, slot),
                }?;
                Ok(tag)
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

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
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

    fn ring_view_tags(
        &self,
        requests: &[RingTagRequest],
    ) -> Result<Vec<ViewTag>, TransactionError> {
        LocalShieldedKeys::from_keypair(self)?.ring_view_tags(requests)
    }
}
