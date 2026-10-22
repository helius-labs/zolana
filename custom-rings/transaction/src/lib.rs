//! Ring output rails as the ring program expands them, mirrored by Go `custom_rings/circuits/base`.

mod published;

use std::collections::{BTreeMap, BTreeSet};

use custom_ring_interface::{
    stream::{DeliveredSlot, PackedSlot, RingSecret, RingTag, SlotSecret, TagIndex},
    RingOutput, RING_DELIVERED_BODY_LEN,
};
use rand::{rngs::OsRng, RngCore};
use zolana_event::MessageData;
use zolana_interface::{instruction::instruction_data::transact::OwnerTag, MAX_OUTPUTS};
use zolana_keypair::{random_salt, viewing_key::Salt, ShieldedAddress, ViewingKey, X25519Pubkey};
use zolana_transaction::{
    instructions::transact::{
        ConfidentialTransaction, OutputEncoder, OutputEncryption, ResolvedOwnerTag, RingOutputSlot,
        SlotEncode, SppProofInputs, SppProofOutputUtxo,
    },
    serialization::{
        confidential::{Confidential, ConfidentialEncode},
        RingDeliveredBody, RingPacked, RingPackedPlaintext, UtxoSerialization,
    },
    Data, TransactionError, SOL_ASSET_ID,
};

pub use published::PublishedSlot;

#[derive(Clone, Debug)]
pub enum RingDelivery {
    /// Scheme 11 sealed to the owner's viewing key, at `PACKED_AUDIT_CAPACITIES`.
    Packed,
    /// Scheme 10 delivered to the owner's viewing key, at `DELIVERED_AUDIT_CAPACITIES`.
    Delivered,
    /// Scheme 9 under a stream tag, each payment delivered to its ring address key.
    Anonymous(Box<AnonymousSlots>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPosition {
    Inbox(TagIndex),
    /// The one pair-anchored payment of a transfer.
    Pair(TagIndex),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPayment {
    /// The ring address key the body opens under.
    pub recipient: X25519Pubkey,
    pub tag: RingTag,
    pub position: StreamPosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousSlot {
    Payment(StreamPayment),
    /// Under a free tag, delivered to the sender's ring change key.
    Change {
        tag: RingTag,
    },
    Exit,
    /// Under a free tag.
    Dummy {
        tag: RingTag,
    },
}

/// The payments of an anonymous transfer by final slot index.
#[must_use]
#[derive(Clone, Debug)]
pub struct AnonymousSlots {
    change_key: X25519Pubkey,
    payments: BTreeMap<u32, StreamPayment>,
    ring_address_keys: BTreeSet<X25519Pubkey>,
    /// Drawn ahead, a change slot's ring secret binds its tag before the owner tags resolve.
    free_tags: [RingTag; MAX_OUTPUTS],
}

impl AnonymousSlots {
    /// `change_key` is the sender's ring change key, the sender finds its change through its spends.
    pub fn new(change_key: X25519Pubkey) -> Self {
        Self {
            change_key,
            payments: BTreeMap::new(),
            ring_address_keys: BTreeSet::new(),
            free_tags: core::array::from_fn(|_| free_tag()),
        }
    }

    /// Refuses a taken slot, a repeated tag and a second pair payment.
    pub fn with_payment(
        mut self,
        slot_index: u32,
        payment: StreamPayment,
    ) -> Result<Self, TransactionError> {
        let paired = |payment: &StreamPayment| matches!(payment.position, StreamPosition::Pair(_));
        if self.payments.contains_key(&slot_index)
            || self.payments.values().any(|other| other.tag == payment.tag)
            || (paired(&payment) && self.payments.values().any(paired))
        {
            return Err(TransactionError::RingPaymentSlot {
                slot_index: slot_index as usize,
            });
        }
        self.ring_address_keys.insert(payment.recipient);
        self.payments.insert(slot_index, payment);
        Ok(self)
    }

    /// The sender's own ring address keys, no exit may name one.
    pub fn with_ring_address_keys(mut self, keys: impl IntoIterator<Item = X25519Pubkey>) -> Self {
        self.ring_address_keys.extend(keys);
        self
    }

    pub fn change_key(&self) -> X25519Pubkey {
        self.change_key
    }

    pub fn payment(&self, slot_index: u32) -> Option<StreamPayment> {
        self.payments.get(&slot_index).copied()
    }

    fn slot(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        slot_index: u32,
    ) -> Result<AnonymousSlot, TransactionError> {
        let index = slot_index as usize;
        let payment = self.payments.get(&slot_index);
        let Some(owner) = output
            .owner_address
            .filter(|_| output.ring_program_id.is_some())
        else {
            if payment.is_some() {
                return Err(TransactionError::RingPaymentSlot { slot_index: index });
            }
            return match output.owner_address {
                Some(owner) if self.ring_address_keys.contains(&owner.viewing_pubkey) => {
                    Err(TransactionError::RingAddressExit { slot_index: index })
                }
                Some(_) => Ok(AnonymousSlot::Exit),
                None => Ok(AnonymousSlot::Dummy {
                    tag: self.free_tag(index)?,
                }),
            };
        };
        match payment {
            Some(payment) if payment.recipient == owner.viewing_pubkey => {
                Ok(AnonymousSlot::Payment(*payment))
            }
            Some(_) => Err(TransactionError::RingPaymentSlot { slot_index: index }),
            None if owner == *sender => Ok(AnonymousSlot::Change {
                tag: self.free_tag(index)?,
            }),
            None => Err(TransactionError::UnplannedRingOutput { slot_index: index }),
        }
    }

    fn free_tag(&self, slot_index: usize) -> Result<RingTag, TransactionError> {
        self.free_tags
            .get(slot_index)
            .copied()
            .ok_or(TransactionError::TooManyOutputs)
    }

    fn check_planned(&self, slots: usize) -> Result<(), TransactionError> {
        match self.payments.keys().find(|index| **index as usize >= slots) {
            Some(index) => Err(TransactionError::RingPaymentSlot {
                slot_index: *index as usize,
            }),
            None => Ok(()),
        }
    }
}

#[must_use]
#[derive(Clone)]
pub struct RingOutputRail {
    tx_viewing_key: ViewingKey,
    salt: Salt,
    delivery: RingDelivery,
}

#[derive(Clone, Copy)]
enum Slot {
    Ring {
        recipient: X25519Pubkey,
        tag: Option<RingTag>,
    },
    Exit,
    Dummy {
        tag: Option<RingTag>,
    },
    Compact,
}

impl RingOutputRail {
    /// A fresh salt per rail, a resent attempt under the same first nullifier repeats no keystream.
    pub fn new(tx_viewing_key: ViewingKey, delivery: RingDelivery) -> Self {
        Self {
            tx_viewing_key,
            salt: random_salt(),
            delivery,
        }
    }

    pub fn encrypt(
        &self,
        transaction: ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<SppProofInputs, TransactionError> {
        OutputEncryption {
            sender,
            tx_viewing_key: &self.tx_viewing_key,
            encoder: self,
        }
        .encrypt(transaction)
    }

    pub fn tx_viewing_key(&self) -> &ViewingKey {
        &self.tx_viewing_key
    }

    pub fn salt(&self) -> Salt {
        self.salt
    }

    pub fn delivery(&self) -> &RingDelivery {
        &self.delivery
    }

    /// The root of the blinding and body key of the ring output at `slot_index`.
    pub fn slot_secret(
        &self,
        recipient: &X25519Pubkey,
        first_nullifier: &[u8; 32],
        slot_index: u32,
    ) -> Result<SlotSecret, TransactionError> {
        Ok(match self.delivery {
            RingDelivery::Packed => PackedSlot {
                tx_viewing_secret: &self.tx_viewing_key.secret_bytes(),
                salt: &self.salt,
                output_index: slot_index,
                first_nullifier,
            }
            .secret()?,
            RingDelivery::Delivered | RingDelivery::Anonymous(_) => DeliveredSlot {
                agreement: &self.tx_viewing_key.ecdh(recipient)?,
                tx_viewing_pk: self.tx_viewing_key.pubkey().as_bytes(),
                recipient_viewing_pk: recipient.as_bytes(),
                salt: &self.salt,
                output_index: slot_index,
                first_nullifier,
            }
            .secret()?,
        })
    }

    fn slot(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        slot_index: u32,
    ) -> Result<Slot, TransactionError> {
        let index = slot_index as usize;
        let delivered = !matches!(self.delivery, RingDelivery::Packed);
        if output.is_compact() {
            return match delivered {
                true => Err(TransactionError::DeliveredCompactPadding { slot_index: index }),
                false => Ok(Slot::Compact),
            };
        }
        let carries_data = !output.data.is_empty()
            || output.data_hash.is_some()
            || output.ring_data_hash.is_some();
        if delivered && !output.is_dummy() && carries_data {
            return Err(TransactionError::DeliveredOutputData { slot_index: index });
        }
        let owner = || {
            output
                .owner_address
                .map(|owner| owner.viewing_pubkey)
                .ok_or(TransactionError::OutputWithoutOwner { slot_index: index })
        };
        Ok(match &self.delivery {
            RingDelivery::Anonymous(slots) => match slots.slot(output, sender, slot_index)? {
                AnonymousSlot::Payment(payment) => Slot::Ring {
                    recipient: payment.recipient,
                    tag: Some(payment.tag),
                },
                AnonymousSlot::Change { tag } => Slot::Ring {
                    recipient: slots.change_key,
                    tag: Some(tag),
                },
                AnonymousSlot::Exit => Slot::Exit,
                AnonymousSlot::Dummy { tag } => Slot::Dummy { tag: Some(tag) },
            },
            RingDelivery::Packed | RingDelivery::Delivered => match output.is_dummy() {
                true => Slot::Dummy { tag: None },
                false if output.is_ring_output() => Slot::Ring {
                    recipient: owner()?,
                    tag: None,
                },
                false => Slot::Exit,
            },
        })
    }

    fn ring_secret_of(
        &self,
        recipient: &X25519Pubkey,
        tag: Option<&RingTag>,
        first_nullifier: &[u8; 32],
        slot_index: u32,
    ) -> Result<RingSecret, TransactionError> {
        let secret = self.slot_secret(recipient, first_nullifier, slot_index)?;
        Ok(match tag {
            Some(tag) => RingSecret::anonymous(&secret, tag)?,
            None => RingSecret::confidential(&secret)?,
        })
    }

    /// The published bytes of a slot through the ring program's own expansion.
    fn framed(
        output: RingOutput<'_>,
        owner_tag: &ResolvedOwnerTag,
        slot_index: usize,
    ) -> Result<MessageData, TransactionError> {
        let framing = || TransactionError::RingOutputFraming { slot_index };
        let expanded = output.transact_output();
        if expanded.owner_tag != owner_tag.tag {
            return Err(framing());
        }
        Ok(MessageData {
            view_tag: owner_tag.resolved,
            data: expanded.data.ok_or_else(framing)?,
        })
    }

    fn dummy_ciphertext(&self, slot: &SlotEncode<'_>) -> Result<Vec<u8>, TransactionError> {
        let plaintext = RingPackedPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 0,
            blinding: [0; 32],
            data: Data::default(),
        }
        .serialize()?;
        Ok(self.tx_viewing_key.encrypt_slot(
            &ViewingKey::new().pubkey(),
            &plaintext,
            self.salt,
            slot.slot_index,
        )?)
    }
}

impl OutputEncoder for RingOutputRail {
    fn ring_secret(&self, slot: &RingOutputSlot<'_>) -> Result<[u8; 32], TransactionError> {
        match self.slot(slot.output, slot.sender, slot.slot_index)? {
            Slot::Ring { recipient, tag } => Ok(*self
                .ring_secret_of(
                    &recipient,
                    tag.as_ref(),
                    &slot.first_nullifier,
                    slot.slot_index,
                )?
                .as_bytes()),
            Slot::Exit | Slot::Dummy { .. } | Slot::Compact => {
                Err(TransactionError::UnexpectedRingSecret {
                    slot_index: slot.slot_index as usize,
                })
            }
        }
    }

    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        if let RingDelivery::Anonymous(slots) = &self.delivery {
            slots.check_planned(transaction.outputs().len())?;
        }
        let mut owner_tags = transaction.owner_tags(&sender.signing_pubkey)?;
        for (index, (output, owner_tag)) in transaction
            .outputs()
            .iter()
            .zip(&mut owner_tags)
            .enumerate()
        {
            let slot_index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let resolved = match self.slot(output, sender, slot_index)? {
                Slot::Compact => continue,
                Slot::Exit => owner_tag.resolved,
                Slot::Ring { tag: Some(tag), .. } | Slot::Dummy { tag: Some(tag) } => tag.field(),
                Slot::Ring {
                    recipient,
                    tag: None,
                } => recipient.u(),
                // A random key publishes as a real recipient's would.
                Slot::Dummy { tag: None } => ViewingKey::new().pubkey().u(),
            };
            *owner_tag = ResolvedOwnerTag {
                tag: OwnerTag::Inline(resolved),
                resolved,
            };
        }
        Ok(owner_tags)
    }

    fn salt(
        &self,
        _tx_viewing_pk: &X25519Pubkey,
        _output_hashes: &[[u8; 32]],
    ) -> Result<Salt, TransactionError> {
        Ok(self.salt)
    }

    fn encode_slot(&self, slot: &SlotEncode<'_>) -> Result<MessageData, TransactionError> {
        let slot_index = slot.slot_index as usize;
        // The expansion ignores the hash, only the published bytes are kept.
        let hash = [0; 32];
        let owner_tag = &slot.owner_tag;
        match self.slot(slot.output, slot.sender, slot.slot_index)? {
            Slot::Compact => Err(TransactionError::DeliveredCompactPadding { slot_index }),
            Slot::Exit => Confidential.encode_slot(slot),
            Slot::Ring {
                recipient,
                tag: None,
            } if matches!(self.delivery, RingDelivery::Packed) => RingPacked::encode_plaintext(
                &RingPackedPlaintext::from(slot.output),
                recipient.u(),
                &ConfidentialEncode {
                    tx: self.tx_viewing_key.clone(),
                    recipient_pubkey: recipient,
                    salt: self.salt,
                    slot_index: slot.slot_index,
                },
            ),
            Slot::Ring { recipient, tag } => {
                let secret =
                    self.slot_secret(&recipient, &slot.first_nullifier, slot.slot_index)?;
                let body = RingDeliveredBody {
                    asset_address: slot.output.asset.asset,
                    amount: slot.output.amount,
                }
                .seal(&secret)?;
                let output = match tag {
                    Some(tag) => RingOutput::Anonymous {
                        hash: &hash,
                        tag,
                        body: &body,
                    },
                    None => RingOutput::Delivered {
                        hash: &hash,
                        u: &owner_tag.resolved,
                        body: &body,
                    },
                };
                Self::framed(output, owner_tag, slot_index)
            }
            Slot::Dummy { tag } => {
                let body = random_body();
                let ciphertext;
                let output = match (tag, &self.delivery) {
                    (Some(tag), _) => RingOutput::Anonymous {
                        hash: &hash,
                        tag,
                        body: &body,
                    },
                    (None, RingDelivery::Packed) => {
                        ciphertext = self.dummy_ciphertext(slot)?;
                        RingOutput::Packed {
                            hash: &hash,
                            u: &owner_tag.resolved,
                            ciphertext: &ciphertext,
                        }
                    }
                    (None, _) => RingOutput::Delivered {
                        hash: &hash,
                        u: &owner_tag.resolved,
                        body: &body,
                    },
                };
                Self::framed(output, owner_tag, slot_index)
            }
        }
    }
}

/// `low128` of a uniform field element, distributed as every stream-derived tag.
fn free_tag() -> RingTag {
    loop {
        let mut value = [0u8; 32];
        OsRng.fill_bytes(&mut value);
        // Uniform below 2^254, `from_field` rejects the draws at or above the modulus.
        value[0] &= 0x3f;
        if let Ok(tag) = RingTag::from_field(&value) {
            return tag;
        }
    }
}

fn random_body() -> [u8; RING_DELIVERED_BODY_LEN] {
    let mut body = [0u8; RING_DELIVERED_BODY_LEN];
    OsRng.fill_bytes(&mut body);
    body
}
