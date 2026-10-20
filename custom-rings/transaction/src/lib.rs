//! The anonymous ring's output rail: scheme-9 slots sealed per recipient stream, one derived
//! tag per slot, framed padding, and one salt per sealed transaction viewing key.

use std::{
    collections::{btree_map::Entry, BTreeMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
};

use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::{
    constants::SALT_LEN, random_salt, viewing_key::ViewTag, RingAddress, ShieldedAddress,
    ViewingKey, X25519Pubkey,
};
pub use zolana_transaction::serialization::ring_anonymous::{
    anonymous_slot_index, ring_anonymous_message, ring_anonymous_padding,
    ring_anonymous_padding_tag, RingAnonymousOutput, RingAnonymousOutputPlaintext,
    RingAnonymousSlot,
};
use zolana_transaction::{
    instructions::transact::{
        ConfidentialTransaction, OutputEncoder, ResolvedOwnerTag, SlotEncode, SppProofOutputUtxo,
    },
    serialization::confidential::Confidential,
    TransactionError,
};

/// The anonymous streams one sender sealed, one salt per transaction viewing key.
#[derive(Default)]
pub struct TransactSession {
    streams: Mutex<BTreeMap<[u8; 33], SealedStream>>,
}

struct SealedStream {
    salt: [u8; SALT_LEN],
    output_hashes: Vec<[u8; 32]>,
}

impl TransactSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// A repeat of the same outputs keeps its salt, other outputs under a sealed key would
    /// key every slot stream twice.
    fn seal(
        &self,
        tx_viewing_pk: &X25519Pubkey,
        output_hashes: &[[u8; 32]],
    ) -> Result<[u8; SALT_LEN], TransactionError> {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        match streams.entry(*tx_viewing_pk.as_bytes()) {
            Entry::Occupied(sealed) if sealed.get().output_hashes == output_hashes => {
                Ok(sealed.get().salt)
            }
            Entry::Occupied(_) => Err(TransactionError::AnonymousStreamReuse),
            Entry::Vacant(stream) => Ok(stream
                .insert(SealedStream {
                    salt: random_salt(),
                    output_hashes: output_hashes.to_vec(),
                })
                .salt),
        }
    }
}

/// The tag an anonymous output publishes and the payer pseudonym its plaintext carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousOutputKeys {
    pub tag: ViewTag,
    pub pair_pk: X25519Pubkey,
}

/// The tags of a transaction's hidden outputs, one per output slot once the slot order is fixed.
#[must_use]
#[derive(Clone)]
pub struct AnonymousViewTags {
    sender: ViewingKey,
    slots: BTreeMap<usize, AnonymousSlotKeys>,
    session: Arc<TransactSession>,
}

#[derive(Clone, Copy)]
struct AnonymousSlotKeys {
    recipient: ShieldedAddress,
    keys: AnonymousOutputKeys,
}

impl AnonymousViewTags {
    pub fn new(sender: &ViewingKey) -> Self {
        Self {
            sender: sender.clone(),
            slots: BTreeMap::new(),
            session: Arc::default(),
        }
    }

    /// Shares the sender's sealed streams across transactions.
    pub fn with_session(mut self, session: Arc<TransactSession>) -> Self {
        self.session = session;
        self
    }

    /// `tag` is reserved on a stream of `address` for output slot `slot`.
    pub fn with_slot(
        mut self,
        slot: usize,
        address: &RingAddress,
        tag: ViewTag,
    ) -> Result<Self, TransactionError> {
        let keys = AnonymousOutputKeys {
            tag,
            pair_pk: self.pair_pk(&address.recipient.viewing_pubkey)?,
        };
        self.slots.insert(
            slot,
            AnonymousSlotKeys {
                recipient: address.recipient,
                keys,
            },
        );
        Ok(self)
    }

    pub fn change_keys(
        &self,
        first_nullifier: &[u8; 32],
        slot: u8,
    ) -> Result<AnonymousOutputKeys, TransactionError> {
        Ok(AnonymousOutputKeys {
            tag: self.sender.ring_change_view_tag(first_nullifier, slot)?,
            pair_pk: self.pair_pk(&self.sender.pubkey())?,
        })
    }

    pub fn blinding_seed(&self, first_nullifier: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        Ok(self.sender.ring_blinding_seed(first_nullifier)?)
    }

    /// The tag and pseudonym a hidden slot publishes, `None` for an exit or a padding slot.
    pub fn slot_keys(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        first_nullifier: &[u8; 32],
        slot_index: usize,
    ) -> Result<Option<AnonymousOutputKeys>, TransactionError> {
        Ok(
            match self.resolve(output, sender, first_nullifier, slot_index)? {
                AnonymousSlot::Hidden(keys) => Some(keys),
                AnonymousSlot::Exit | AnonymousSlot::Padding => None,
            },
        )
    }

    fn pair_pk(&self, recipient: &X25519Pubkey) -> Result<X25519Pubkey, TransactionError> {
        Ok(self.sender.pair_key(recipient)?.pubkey())
    }

    fn resolve(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        first_nullifier: &[u8; 32],
        slot_index: usize,
    ) -> Result<AnonymousSlot, TransactionError> {
        if output.is_compact() {
            return Err(TransactionError::AnonymousCompactPadding { slot_index });
        }
        let Some(owner) = output.owner_address else {
            return Ok(AnonymousSlot::Padding);
        };
        if output.ring_program_id.is_none() {
            return Ok(AnonymousSlot::Exit);
        }
        if !output.data.is_empty() {
            return Err(TransactionError::AnonymousOutputData { slot_index });
        }
        if owner.signing_pubkey == sender.signing_pubkey {
            return Ok(AnonymousSlot::Hidden(self.change_keys(
                first_nullifier,
                anonymous_slot_index(slot_index)?,
            )?));
        }
        match self.slots.get(&slot_index) {
            Some(slot) if slot.recipient == owner => Ok(AnonymousSlot::Hidden(slot.keys)),
            _ => Err(TransactionError::UnknownAnonymousRecipient { slot_index }),
        }
    }

    fn resolve_all(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<AnonymousSlot>, TransactionError> {
        transaction
            .outputs()
            .iter()
            .enumerate()
            .map(|(slot_index, output)| {
                self.resolve(output, sender, transaction.first_nullifier(), slot_index)
            })
            .collect()
    }

    /// Every slot's tag in order, a padding tag drawn from `sample` until it differs from
    /// every other tag of the transaction.
    fn published_tags(
        slots: &[AnonymousSlot],
        owner_tags: &[ResolvedOwnerTag],
        mut sample: impl FnMut() -> ViewTag,
    ) -> Result<Vec<ViewTag>, TransactionError> {
        let mut taken: HashSet<ViewTag> = HashSet::new();
        let mut tags = Vec::with_capacity(slots.len());
        for (index, (slot, owner_tag)) in slots.iter().zip(owner_tags).enumerate() {
            let tag = match slot {
                AnonymousSlot::Hidden(keys) => keys.tag,
                // Exits publish owner keys, two exits to one owner share theirs.
                AnonymousSlot::Exit => {
                    taken.insert(owner_tag.resolved);
                    tags.push(owner_tag.resolved);
                    continue;
                }
                AnonymousSlot::Padding => {
                    tags.push([0; 32]);
                    continue;
                }
            };
            if !taken.insert(tag) {
                let first = tags
                    .iter()
                    .position(|earlier| *earlier == tag)
                    .unwrap_or(index);
                return Err(TransactionError::DuplicateAnonymousTag {
                    first,
                    second: index,
                });
            }
            tags.push(tag);
        }
        for (tag, slot) in tags.iter_mut().zip(slots) {
            if matches!(slot, AnonymousSlot::Padding) {
                *tag = loop {
                    let candidate = sample();
                    if taken.insert(candidate) {
                        break candidate;
                    }
                };
            }
        }
        Ok(tags)
    }
}

impl OutputEncoder for AnonymousViewTags {
    fn output_blinding_seed(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Option<[u8; 32]>, TransactionError> {
        if self.sender.pubkey() != sender.viewing_pubkey {
            return Err(TransactionError::AnonymousViewTagsSenderMismatch);
        }
        Ok(Some(self.blinding_seed(transaction.first_nullifier())?))
    }

    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        let slots = self.resolve_all(transaction, sender)?;
        let mut owner_tags = transaction.owner_tags(&sender.signing_pubkey)?;
        let tags = Self::published_tags(&slots, &owner_tags, ring_anonymous_padding_tag)?;
        for ((owner_tag, slot), tag) in owner_tags.iter_mut().zip(&slots).zip(tags) {
            if !matches!(slot, AnonymousSlot::Exit) {
                *owner_tag = ResolvedOwnerTag {
                    tag: OwnerTag::Inline(tag),
                    resolved: tag,
                };
            }
        }
        Ok(owner_tags)
    }

    fn salt(
        &self,
        tx_viewing_pk: &X25519Pubkey,
        output_hashes: &[[u8; 32]],
    ) -> Result<[u8; SALT_LEN], TransactionError> {
        self.session.seal(tx_viewing_pk, output_hashes)
    }

    fn encode_slot(&self, slot: &SlotEncode<'_>) -> Result<MessageData, TransactionError> {
        let slot_index = slot.slot_index as usize;
        match self.resolve(slot.output, slot.sender, &slot.first_nullifier, slot_index)? {
            AnonymousSlot::Hidden(keys) => seal_hidden(slot, keys),
            AnonymousSlot::Padding => ring_anonymous_padding(slot.owner_tag.resolved),
            AnonymousSlot::Exit => Confidential.encode_slot(slot),
        }
    }
}

#[derive(Clone, Copy)]
enum AnonymousSlot {
    Hidden(AnonymousOutputKeys),
    /// A default-ring note, the circuit publishes its owner's Solana key.
    Exit,
    Padding,
}

/// The owner's note inside an anonymous ring, the recipient viewing key stays off the wire.
fn seal_hidden(
    slot: &SlotEncode<'_>,
    keys: AnonymousOutputKeys,
) -> Result<MessageData, TransactionError> {
    let slot_index = slot.slot_index as usize;
    let output = slot.output;
    let address = output
        .owner_address
        .ok_or(TransactionError::OutputWithoutOwner { slot_index })?;
    let stream = RingAnonymousSlot {
        tx_viewing_pk: slot.tx_viewing_key.pubkey(),
        recipient_pk: address.viewing_pubkey,
        salt: slot.salt,
        slot: anonymous_slot_index(slot_index)?,
    };
    let opening = RingAnonymousOutputPlaintext {
        asset_address: *output.asset.asset.as_array(),
        amount: output.amount,
        blinding: output.blinding,
        pair_u: keys.pair_pk.u(),
    };
    ring_anonymous_message(&stream.seal(slot.tx_viewing_key, &opening)?, keys.tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(tag: ViewTag) -> ResolvedOwnerTag {
        ResolvedOwnerTag {
            tag: OwnerTag::Inline(tag),
            resolved: tag,
        }
    }

    fn hidden(tag: ViewTag) -> AnonymousSlot {
        AnonymousSlot::Hidden(AnonymousOutputKeys {
            tag,
            pair_pk: ViewingKey::new().pubkey(),
        })
    }

    /// A padding tag equal to a hidden, exit or earlier padding tag is drawn again.
    #[test]
    fn padding_tags_are_resampled_on_collision() {
        let real = [1; 32];
        let exit = [2; 32];
        let slots = [
            hidden(real),
            AnonymousSlot::Exit,
            AnonymousSlot::Padding,
            AnonymousSlot::Padding,
        ];
        let owner_tags = [
            resolved([0; 32]),
            resolved(exit),
            resolved([0; 32]),
            resolved([0; 32]),
        ];
        let mut draws = [real, exit, [3; 32], [3; 32], [4; 32]].into_iter();
        let tags = AnonymousViewTags::published_tags(&slots, &owner_tags, || {
            draws.next().expect("a draw per attempt")
        })
        .unwrap();
        assert_eq!(tags, [real, exit, [3; 32], [4; 32]]);
        assert!(draws.next().is_none());
    }

    #[test]
    fn two_hidden_slots_never_share_a_tag() {
        let slots = [hidden([1; 32]), hidden([1; 32])];
        let owner_tags = [resolved([0; 32]); 2];
        assert!(matches!(
            AnonymousViewTags::published_tags(&slots, &owner_tags, ring_anonymous_padding_tag),
            Err(TransactionError::DuplicateAnonymousTag {
                first: 0,
                second: 1
            })
        ));
    }
}
