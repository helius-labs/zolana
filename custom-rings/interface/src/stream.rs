//! Tag streams, slot secrets, ring secrets and the sender commitment of ring
//! transfers, mirrored by the Go package `custom_rings/circuits/base`.

use thiserror::Error;
use zolana_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, right_align},
    Hasher, HasherError, Poseidon,
};

use crate::{domain, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG};

/// `epoch = slot / EPOCH_SLOTS`, the statement epoch the program derives.
pub const EPOCH_SLOTS: u64 = 1 << 18;
/// A 6-bit index in the circuit.
pub const J_INBOX: u8 = 64;
/// One index range check serves both streams.
pub const J_PAIR: u8 = J_INBOX;
/// Epochs a pair stream lives after its anchor, a 5-bit difference in the circuit.
pub const K_PAIR_EPOCHS: u64 = 32;
/// `low128` bytes, the owner tag is `0^16 ‖ tag`.
pub const TAG_LEN: usize = 16;

#[derive(Debug, Error, PartialEq)]
pub enum StreamError {
    #[error("tag index {0} is outside its stream")]
    IndexOutOfRange(u8),
    #[error("value is not a canonical field element")]
    NoncanonicalField,
    #[error("viewing key is not tagged 0x04")]
    UntaggedKey,
    #[error(transparent)]
    Hasher(#[from] HasherError),
}

pub const fn tag_epoch(slot: u64) -> u64 {
    slot / EPOCH_SLOTS
}

/// Below `J_INBOX`, the only indexes a proof accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagIndex(u8);

impl TagIndex {
    pub fn new(index: u8) -> Result<Self, StreamError> {
        if index < J_INBOX {
            Ok(Self(index))
        } else {
            Err(StreamError::IndexOutOfRange(index))
        }
    }

    pub fn all() -> impl Iterator<Item = Self> {
        (0..J_INBOX).map(Self)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Its secret is known only to the sender and the auditor of `tx_sk`.
pub struct PackedSlot<'a> {
    /// The clamped encoding the auditor envelope seals.
    pub tx_viewing_secret: &'a [u8; 32],
    pub salt: &'a [u8; 16],
    pub output_index: u32,
    pub first_nullifier: &'a [u8; 32],
}

impl PackedSlot<'_> {
    /// `Poseidon(CRAS, pack_be(tx_sk), salt, i, n0)`, `n0` keeps a reused key and salt from repeating it.
    pub fn secret(self) -> Result<SlotSecret, HasherError> {
        let [key0, key1] = pack_be(self.tx_viewing_secret);
        Ok(SlotSecret(Poseidon::hashv(&[
            &domain::field(domain::PACKED_SLOT_SECRET),
            &key0,
            &key1,
            &right_align(self.salt),
            &right_align(&self.output_index.to_be_bytes()),
            self.first_nullifier,
        ])?))
    }
}

/// Its secret is rebuilt by the recipient from `X25519(u_sk, tx_u)`.
pub struct DeliveredSlot<'a> {
    /// `X25519(tx_sk, u)`.
    pub agreement: &'a [u8; 32],
    pub tx_viewing_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub recipient_viewing_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub salt: &'a [u8; 16],
    pub output_index: u32,
    pub first_nullifier: &'a [u8; 32],
}

impl DeliveredSlot<'_> {
    /// `Poseidon(CRDS, pack_be(dh), pack_be(tx_viewing_pk), pack_be(recipient_viewing_pk), salt, i, n0)`.
    pub fn secret(self) -> Result<SlotSecret, StreamError> {
        let [dh0, dh1] = pack_be(self.agreement);
        let [tx0, tx1] = tagged_key_fields(self.tx_viewing_pk)?;
        let [r0, r1] = tagged_key_fields(self.recipient_viewing_pk)?;
        Ok(SlotSecret(Poseidon::hashv(&[
            &domain::field(domain::DELIVERED_SLOT_SECRET),
            &dh0,
            &dh1,
            &tx0,
            &tx1,
            &r0,
            &r1,
            &right_align(self.salt),
            &right_align(&self.output_index.to_be_bytes()),
            self.first_nullifier,
        ])?))
    }
}

/// The root of a ring output's blinding, on a delivered rail also of its body key and pair key.
#[derive(Clone)]
pub struct SlotSecret([u8; 32]);

impl SlotSecret {
    /// Every slot secret is a Poseidon output, a non-canonical value is refused.
    pub fn new(bytes: [u8; 32]) -> Result<Self, StreamError> {
        canonical(bytes).map(Self)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `Poseidon(CRIK, ring_id, pack_be(viewing_pk))`, public to anyone holding the ring address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxKey([u8; 32]);

impl InboxKey {
    /// `viewing_pk` is the per-address key `0x04 ‖ u` of a ring address.
    pub fn derive(
        ring_id: &[u8; 32],
        viewing_pk: &[u8; TAGGED_X25519_KEY_LEN],
    ) -> Result<Self, StreamError> {
        let [r0, r1] = tagged_key_fields(viewing_pk)?;
        Ok(Self(Poseidon::hashv(&[
            &domain::field(domain::INBOX_KEY),
            ring_id,
            &r0,
            &r1,
        ])?))
    }

    /// `low128(Poseidon(CRIT, inbox_key, epoch, j))`.
    pub fn tag(&self, epoch: u64, index: TagIndex) -> Result<RingTag, HasherError> {
        Stream {
            domain: domain::INBOX_TAG,
            key: &self.0,
        }
        .tag(epoch, index)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `Poseidon(CRPK, s1)`, a secret of the sender, the recipient and the auditor of the first contact.
#[derive(Clone)]
pub struct PairKey([u8; 32]);

impl PairKey {
    /// `first_contact` is the delivered slot secret of the anchor.
    pub fn derive(first_contact: &SlotSecret) -> Result<Self, HasherError> {
        Ok(Self(Poseidon::hashv(&[
            &domain::field(domain::PAIR_KEY),
            &first_contact.0,
        ])?))
    }

    /// A pair key a wallet stored, every pair key is a Poseidon output.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, StreamError> {
        canonical(bytes).map(Self)
    }

    /// `low128(Poseidon(CRPT, pair_key, epoch, j))`, live `K_PAIR_EPOCHS` after the anchor.
    pub fn tag(&self, epoch: u64, index: TagIndex) -> Result<RingTag, HasherError> {
        Stream {
            domain: domain::PAIR_TAG,
            key: &self.0,
        }
        .tag(epoch, index)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `low128` of a canonical field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RingTag([u8; TAG_LEN]);

impl RingTag {
    /// The circuit reads `low128` of the reduced value, a non-canonical encoding is refused.
    pub fn from_field(value: &[u8; 32]) -> Result<Self, StreamError> {
        canonical(*value).map(|value| Self::low128(&value))
    }

    pub const fn from_bytes(bytes: [u8; TAG_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }

    /// `0^16 ‖ tag`, the expanded owner tag and the field the statement chains.
    pub fn field(&self) -> [u8; 32] {
        right_align(&self.0)
    }

    /// `None` unless the first 16 bytes are zero, the one owner tag form of an anonymous slot.
    pub fn from_owner_tag(owner_tag: &[u8; 32]) -> Option<Self> {
        let (padding, tag) = owner_tag.split_at(32 - TAG_LEN);
        padding
            .iter()
            .all(|byte| *byte == 0)
            .then(|| Self(core::array::from_fn(|i| tag[i])))
    }

    /// Unchecked, a Poseidon output is below the modulus.
    fn low128(value: &[u8; 32]) -> Self {
        Self(core::array::from_fn(|i| value[32 - TAG_LEN + i]))
    }
}

/// SPP's private ring output blinding input, bound to its slot secret by the audit proof alone.
#[derive(Clone)]
pub struct RingSecret([u8; 32]);

impl RingSecret {
    /// `Poseidon(CRRC, s)`, a confidential or delegate ring secret no anchor accepts.
    pub fn confidential(slot_secret: &SlotSecret) -> Result<Self, HasherError> {
        Ok(Self(Poseidon::hashv(&[
            &domain::field(domain::CONFIDENTIAL_RING_SECRET),
            &slot_secret.0,
        ])?))
    }

    /// `Poseidon(CRRA, s, tag)`, the one form an anchor opens, binding the published tag.
    pub fn anonymous(slot_secret: &SlotSecret, tag: &RingTag) -> Result<Self, HasherError> {
        Ok(Self(Poseidon::hashv(&[
            &domain::field(domain::ANONYMOUS_RING_SECRET),
            &slot_secret.0,
            &tag.field(),
        ])?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `Poseidon(CRSC, sender_pk_hash, private_tx_blinding)`, binding the audit and
/// policy proofs to one hidden sender.
pub struct SenderCommitment {
    pub sender_pk_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl SenderCommitment {
    pub fn derive(self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::SENDER_COMMITMENT),
            &self.sender_pk_hash,
            &self.private_tx_blinding,
        ])
    }
}

struct Stream<'a> {
    domain: u32,
    key: &'a [u8; 32],
}

impl Stream<'_> {
    fn tag(self, epoch: u64, index: TagIndex) -> Result<RingTag, HasherError> {
        let digest = Poseidon::hashv(&[
            &domain::field(self.domain),
            self.key,
            &right_align(&epoch.to_be_bytes()),
            &right_align(&[index.0]),
        ])?;
        Ok(RingTag::low128(&digest))
    }
}

fn tagged_key_fields(key: &[u8; TAGGED_X25519_KEY_LEN]) -> Result<[[u8; 32]; 2], StreamError> {
    if key[0] != VIEWING_PUBKEY_TAG {
        return Err(StreamError::UntaggedKey);
    }
    Ok(pack_be(key))
}

fn canonical(value: [u8; 32]) -> Result<[u8; 32], StreamError> {
    if is_canonical_bn254_scalar_be(&value) {
        Ok(value)
    } else {
        Err(StreamError::NoncanonicalField)
    }
}

#[cfg(test)]
mod tests {
    use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

    use super::*;

    #[test]
    fn tag_index_stops_at_the_stream_end() {
        assert_eq!(
            TagIndex::new(J_INBOX - 1).map(TagIndex::get),
            Ok(J_INBOX - 1)
        );
        assert_eq!(
            TagIndex::new(J_INBOX),
            Err(StreamError::IndexOutOfRange(J_INBOX))
        );
        assert_eq!(TagIndex::all().last().map(TagIndex::get), Some(J_INBOX - 1));
    }

    #[test]
    fn ring_tag_refuses_the_modulus() {
        let mut below = BN254_SCALAR_MODULUS_BE;
        below[31] -= 1;
        assert!(RingTag::from_field(&below).is_ok());
        assert_eq!(
            RingTag::from_field(&BN254_SCALAR_MODULUS_BE),
            Err(StreamError::NoncanonicalField)
        );
    }

    /// The program writes the 16 zero bytes, an owner tag with any other prefix is no anonymous tag.
    #[test]
    fn an_owner_tag_opens_only_behind_sixteen_zero_bytes() {
        let tag = RingTag::from_bytes([9; TAG_LEN]);
        assert_eq!(RingTag::from_owner_tag(&tag.field()), Some(tag));
        for index in 0..32 - TAG_LEN {
            let mut marked = tag.field();
            marked[index] = 1;
            assert_eq!(RingTag::from_owner_tag(&marked), None);
        }
    }

    /// A recipient deriving from a mistagged key would scan tags no sender proves.
    #[test]
    fn untagged_viewing_keys_are_refused() {
        let tagged = [VIEWING_PUBKEY_TAG; TAGGED_X25519_KEY_LEN];
        let mut untagged = tagged;
        untagged[0] = 0x02;
        assert_eq!(
            InboxKey::derive(&[0; 32], &untagged),
            Err(StreamError::UntaggedKey)
        );
        let slot = |recipient_viewing_pk| DeliveredSlot {
            agreement: &[1; 32],
            tx_viewing_pk: &tagged,
            recipient_viewing_pk,
            salt: &[2; 16],
            output_index: 0,
            first_nullifier: &[0; 32],
        };
        assert!(slot(&tagged).secret().is_ok());
        assert!(matches!(
            slot(&untagged).secret(),
            Err(StreamError::UntaggedKey)
        ));
    }
}
