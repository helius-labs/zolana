//! The auditor envelope, CROD pad and disclosures, mirrored by Go `custom_rings/circuits/base`.

use custom_ring_interface::{
    domain, pack_disclosure, unpack_disclosure, AnonymousAuditKey, AnonymousLayout,
    DeliveredLayout, DisclosureLayout, PackedFields, PackedLayout, ANONYMOUS_ENTRY_CLASS,
    ANONYMOUS_SLOT_BYTES, AUDIT_CIPHERTEXT_LEN, DELIVERED_SLOT_BYTES,
    DISCLOSURE_INPUT_AMOUNT_BYTES, DISCLOSURE_SENDER_KEY_BYTES,
};
use zeroize::Zeroizing;
use zolana_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, pack_be_chunks, right_align},
    Hasher, Poseidon,
};
use zolana_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use zolana_transaction::field::{field_add, field_sub};

use crate::{
    encryption::{open_stream, seal_stream, StreamSchedule},
    AuditError,
};

const KEY_BYTES: usize = 32;
const AMOUNT_BYTES: usize = 8;
const KEY_AND_AMOUNT_BYTES: usize = KEY_BYTES + AMOUNT_BYTES;
const ZERO: [u8; 32] = [0; 32];

const _: () = assert!(DELIVERED_SLOT_BYTES == KEY_AND_AMOUNT_BYTES);
const _: () = assert!(ANONYMOUS_SLOT_BYTES == 2 * KEY_BYTES);
const _: () = assert!(DISCLOSURE_INPUT_AMOUNT_BYTES == AMOUNT_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEnvelope {
    pub eph_u: [u8; 32],
    pub sealed: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// The audit proof witnesses `ephemeral_sk`.
pub struct SealedAuditEnvelope {
    pub envelope: AuditEnvelope,
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
}

impl AuditEnvelope {
    /// A fresh ephemeral key per call, a reused one repeats the keystream under the auditor key.
    pub fn seal(
        tx_viewing_key: &ViewingKey,
        auditor_pk: &X25519Pubkey,
    ) -> Result<SealedAuditEnvelope, AuditError> {
        let ephemeral = X25519Keypair::new();
        let mut sealed = tx_viewing_key.secret_bytes();
        seal_stream(&ephemeral, auditor_pk, StreamSchedule::Audit, &mut *sealed)?;
        Ok(SealedAuditEnvelope {
            envelope: Self {
                eph_u: ephemeral.pubkey().u(),
                sealed: *sealed,
            },
            ephemeral_sk: ephemeral.secret_bytes(),
        })
    }

    /// The circuit seals the clamped encoding, an unclamped alias of the same key is refused.
    pub fn open(&self, auditor: &X25519Keypair) -> Result<ViewingKey, AuditError> {
        let mut secret = Zeroizing::new(self.sealed);
        open_stream(
            auditor,
            &X25519Pubkey::from_u(self.eph_u)?,
            StreamSchedule::Audit,
            &mut *secret,
        )?;
        ViewingKey::from_canonical_bytes(&secret).map_err(|_| AuditError::NonCanonicalViewingKey)
    }
}

/// `pad_j = Poseidon(seed, j)`, a known pad reveals no other.
pub struct DisclosurePad {
    seed: Zeroizing<[u8; 32]>,
}

impl DisclosurePad {
    /// `seed = Poseidon(CROD, pack_be(tx_sk), salt)`.
    pub fn new(tx_viewing_key: &ViewingKey, salt: &[u8; 16]) -> Result<Self, AuditError> {
        Self::keyed(
            &domain::field(domain::DISCLOSURE_PAD),
            &tx_viewing_key.secret_bytes(),
            salt,
        )
    }

    pub(crate) fn keyed(
        domain: &[u8; 32],
        key: &[u8; 32],
        salt: &[u8; 16],
    ) -> Result<Self, AuditError> {
        let [key0, key1] = pack_be(key);
        Ok(Self {
            seed: Zeroizing::new(Poseidon::hashv(&[
                domain,
                &key0,
                &key1,
                &right_align(salt),
            ])?),
        })
    }

    /// `C_j = P_j + pad_j mod q`.
    pub fn encrypt(&self, plaintext: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, AuditError> {
        self.apply(plaintext, field_add)
    }

    pub fn decrypt(&self, published: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, AuditError> {
        self.apply(published, field_sub)
    }

    fn apply(
        &self,
        fields: &[[u8; 32]],
        combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        (0u64..)
            .zip(fields)
            .map(|(index, field)| {
                let pad = Poseidon::hashv(&[&*self.seed, &right_align(&index.to_be_bytes())])?;
                Ok(combine(&canonical(*field)?, &pad))
            })
            .collect()
    }
}

/// One published packed slot, ring output or exit alike.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackedOutputOpening {
    pub owner_key: [u8; 32],
    /// `None` under key escrow, the owner's record escrows it.
    pub nullifier_pk: Option<[u8; 32]>,
    pub asset: [u8; 32],
    pub amount: u64,
    /// Zero on a data-free transfer.
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

/// The body opens the rest of a ring output, an exit's owner is its owner tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveredOutputOpening {
    Ring {
        owner_key: [u8; 32],
        nullifier_pk: Option<[u8; 32]>,
    },
    Exit {
        nullifier_pk: Option<[u8; 32]>,
        asset: [u8; 32],
        amount: u64,
    },
    Dummy,
}

/// The published tag hides `recipient_u`, only the disclosure names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousOutputOpening {
    Ring {
        owner_key: [u8; 32],
        nullifier_pk: [u8; 32],
        recipient_u: [u8; 32],
    },
    Exit {
        nullifier_pk: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    },
    Dummy,
}

/// A spent UTXO of the hidden sender, its data hashes zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnonymousInputOpening {
    pub asset: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
}

/// A `None` input is a dummy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnonymousInputs {
    /// Every spent UTXO a ring note, the auditor opens it by its UTXO hash.
    Commitments(Vec<Option<[u8; 32]>>),
    /// The entry key opens every spent UTXO, all under one nullifier key.
    Openings {
        sender_nullifier_pk: [u8; 32],
        inputs: Vec<Option<AnonymousInputOpening>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousDisclosure {
    pub layout: AnonymousLayout,
    pub seed_out: Option<[u8; 32]>,
    pub sender_key: [u8; 32],
    pub outputs: Vec<AnonymousOutputOpening>,
    pub inputs: AnonymousInputs,
}

/// `seed_out` is present exactly when an output exits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditDisclosure {
    /// A `None` output is a dummy.
    Packed {
        layout: PackedLayout,
        seed_out: Option<[u8; 32]>,
        outputs: Vec<Option<PackedOutputOpening>>,
    },
    Delivered {
        layout: DeliveredLayout,
        seed_out: Option<[u8; 32]>,
        outputs: Vec<DeliveredOutputOpening>,
    },
    Anonymous(AnonymousDisclosure),
}

/// A ring slot and an exit share a byte width, the exit bitmap tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedOutputs<'a> {
    pub layout: DisclosureLayout,
    /// One per published slot.
    pub exits: &'a [bool],
}

impl AuditDisclosure {
    pub fn layout(&self) -> DisclosureLayout {
        match self {
            Self::Packed { layout, .. } => DisclosureLayout::Packed(*layout),
            Self::Delivered { layout, .. } => DisclosureLayout::Delivered(*layout),
            Self::Anonymous(disclosure) => DisclosureLayout::Anonymous(disclosure.layout),
        }
    }

    /// The plaintext `P` the pad masks.
    pub fn fields(&self) -> Result<Vec<[u8; 32]>, AuditError> {
        let mut fields = vec![ZERO; self.layout().field_count()];
        match self {
            Self::Packed {
                layout,
                seed_out,
                outputs,
            } => {
                let at = layout.fields();
                check_len(outputs.len(), layout.outputs)?;
                place_seed_out(&mut fields, at.seed_out, *seed_out)?;
                for (index, opening) in outputs.iter().enumerate() {
                    let start = at.first_slot + index * at.slot_width;
                    let slot = &mut fields[start..start + at.slot_width];
                    if let Some(opening) = opening {
                        opening.place(slot, &at)?;
                    }
                }
            }
            Self::Delivered {
                layout,
                seed_out,
                outputs,
            } => {
                let at = layout.fields();
                check_len(outputs.len(), layout.outputs)?;
                place_seed_out(&mut fields, at.seed_out, *seed_out)?;
                match &at.nullifier_pks {
                    Some(range) => fields[range.clone()].copy_from_slice(
                        &outputs
                            .iter()
                            .map(DeliveredOutputOpening::published_nullifier_pk)
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                    None if outputs.iter().any(|output| output.nullifier_pk().is_some()) => {
                        return Err(AuditError::DisclosureLayout)
                    }
                    None => {}
                }
                let mut slots = Vec::with_capacity(at.slot_bytes * outputs.len());
                for output in outputs {
                    slots.extend(output.slot_bytes(at.slot_bytes)?);
                }
                fields[at.slots].copy_from_slice(&pack_disclosure(&slots));
            }
            Self::Anonymous(disclosure) => disclosure.place(&mut fields)?,
        }
        fields.into_iter().map(canonical).collect()
    }

    /// Refuses a field at or above the modulus and any nonzero padding.
    pub fn decode(
        published: PublishedOutputs<'_>,
        fields: &[[u8; 32]],
    ) -> Result<Self, AuditError> {
        let PublishedOutputs { layout, exits } = published;
        if fields.len() != layout.field_count() {
            return Err(AuditError::DisclosureLayout);
        }
        fields
            .iter()
            .try_for_each(|field| canonical(*field).map(drop))?;
        Ok(match layout {
            DisclosureLayout::Packed(layout) => {
                check_len(exits.len(), layout.outputs)?;
                let at = layout.fields();
                let outputs = (0..layout.outputs)
                    .map(|index| {
                        let start = at.first_slot + index * at.slot_width;
                        PackedOutputOpening::read(&fields[start..start + at.slot_width], &at)
                    })
                    .collect::<Result<_, _>>()?;
                Self::Packed {
                    layout,
                    seed_out: at.seed_out.map(|index| fields[index]),
                    outputs,
                }
            }
            DisclosureLayout::Delivered(layout) => {
                check_len(exits.len(), layout.outputs)?;
                let at = layout.fields();
                if !layout.exits && exits.contains(&true) {
                    return Err(AuditError::DisclosureLayout);
                }
                let nullifier_pks = at.nullifier_pks.clone().map(|range| &fields[range]);
                let slots =
                    packed_bytes(&fields[at.slots.clone()], at.slot_bytes * layout.outputs)?;
                let outputs = slots
                    .chunks(at.slot_bytes)
                    .zip(exits)
                    .enumerate()
                    .map(|(index, (slot, exit))| {
                        DeliveredOutputOpening::read(
                            nullifier_pks.map(|pks| pks[index]),
                            slot,
                            *exit,
                        )
                    })
                    .collect::<Result<_, _>>()?;
                Self::Delivered {
                    layout,
                    seed_out: at.seed_out.map(|index| fields[index]),
                    outputs,
                }
            }
            DisclosureLayout::Anonymous(layout) => {
                check_len(exits.len(), layout.outputs)?;
                Self::Anonymous(AnonymousDisclosure::read(layout, exits, fields)?)
            }
        })
    }
}

impl PackedOutputOpening {
    fn place(&self, slot: &mut [[u8; 32]], at: &PackedFields) -> Result<(), AuditError> {
        match (at.nullifier_pk, self.nullifier_pk) {
            (Some(offset), Some(nullifier_pk)) => slot[offset] = nullifier_pk,
            (None, None) => {}
            _ => return Err(AuditError::DisclosureLayout),
        }
        slot[at.asset] = self.asset;
        match at.data_hashes {
            Some(offset) => {
                slot[offset] = self.data_hash;
                slot[offset + 1] = self.ring_data_hash;
            }
            None if self.data_hash != ZERO || self.ring_data_hash != ZERO => {
                return Err(AuditError::DisclosureLayout)
            }
            None => {}
        }
        let packed = pack_disclosure(&key_and_amount(&self.owner_key, self.amount));
        slot[at.owner_and_amount..at.owner_and_amount + packed.len()].copy_from_slice(&packed);
        Ok(())
    }

    fn read(slot: &[[u8; 32]], at: &PackedFields) -> Result<Option<Self>, AuditError> {
        if slot.iter().all(|field| *field == ZERO) {
            return Ok(None);
        }
        let (data_hash, ring_data_hash) = at
            .data_hashes
            .map_or((ZERO, ZERO), |offset| (slot[offset], slot[offset + 1]));
        let packed = packed_bytes(
            &slot[at.owner_and_amount..at.owner_and_amount + pack_be_chunks(KEY_AND_AMOUNT_BYTES)],
            KEY_AND_AMOUNT_BYTES,
        )?;
        let (owner_key, amount) = split_key_and_amount(
            packed
                .as_slice()
                .try_into()
                .map_err(|_| AuditError::DisclosureLayout)?,
        );
        Ok(Some(Self {
            owner_key,
            nullifier_pk: at.nullifier_pk.map(|offset| slot[offset]),
            asset: slot[at.asset],
            amount,
            data_hash,
            ring_data_hash,
        }))
    }
}

impl DeliveredOutputOpening {
    fn nullifier_pk(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ring { nullifier_pk, .. } | Self::Exit { nullifier_pk, .. } => *nullifier_pk,
            Self::Dummy => None,
        }
    }

    fn published_nullifier_pk(&self) -> Result<[u8; 32], AuditError> {
        match self {
            Self::Dummy => Ok(ZERO),
            _ => self.nullifier_pk().ok_or(AuditError::DisclosureLayout),
        }
    }

    fn slot_bytes(&self, width: usize) -> Result<Vec<u8>, AuditError> {
        let full = match self {
            Self::Ring { owner_key, .. } => key_and_amount(owner_key, 0),
            Self::Exit { .. } if width != DELIVERED_SLOT_BYTES => {
                return Err(AuditError::DisclosureLayout)
            }
            Self::Exit { asset, amount, .. } => key_and_amount(&canonical(*asset)?, *amount),
            Self::Dummy => [0; DELIVERED_SLOT_BYTES],
        };
        Ok(full[..width].to_vec())
    }

    fn read(nullifier_pk: Option<[u8; 32]>, slot: &[u8], exit: bool) -> Result<Self, AuditError> {
        let head: [u8; KEY_BYTES] = slot
            .get(..KEY_BYTES)
            .and_then(|head| head.try_into().ok())
            .ok_or(AuditError::DisclosureLayout)?;
        let tail = &slot[KEY_BYTES..];
        if exit {
            let amount: [u8; AMOUNT_BYTES] =
                tail.try_into().map_err(|_| AuditError::DisclosureLayout)?;
            return Ok(Self::Exit {
                nullifier_pk,
                asset: canonical(head)?,
                amount: u64::from_be_bytes(amount),
            });
        }
        // A disclosed zero key marks a dummy, under key escrow its zero slot does.
        let dummy = match nullifier_pk {
            Some(nullifier_pk) => nullifier_pk == ZERO,
            None => head == ZERO,
        };
        if dummy {
            return zero(slot).map(|()| Self::Dummy);
        }
        zero(tail)?;
        Ok(Self::Ring {
            owner_key: head,
            nullifier_pk,
        })
    }
}

impl AnonymousOutputOpening {
    fn nullifier_pk(&self) -> [u8; 32] {
        match self {
            Self::Ring { nullifier_pk, .. } | Self::Exit { nullifier_pk, .. } => *nullifier_pk,
            Self::Dummy => ZERO,
        }
    }

    fn slot_bytes(&self) -> Result<[u8; ANONYMOUS_SLOT_BYTES], AuditError> {
        let mut slot = [0; ANONYMOUS_SLOT_BYTES];
        let (head, tail) = slot.split_at_mut(KEY_BYTES);
        match self {
            Self::Ring {
                owner_key,
                recipient_u,
                ..
            } => {
                head.copy_from_slice(owner_key);
                tail.copy_from_slice(recipient_u);
            }
            Self::Exit { asset, amount, .. } => {
                head.copy_from_slice(&canonical(*asset)?);
                tail[..AMOUNT_BYTES].copy_from_slice(&amount.to_be_bytes());
            }
            Self::Dummy => {}
        }
        Ok(slot)
    }

    fn read(
        nullifier_pk: [u8; 32],
        slot: &[u8; ANONYMOUS_SLOT_BYTES],
        exit: bool,
    ) -> Result<Self, AuditError> {
        let head: [u8; KEY_BYTES] = core::array::from_fn(|i| slot[i]);
        let tail: [u8; KEY_BYTES] = core::array::from_fn(|i| slot[KEY_BYTES + i]);
        let (amount, padding) = split_exit_tail(&tail);
        match exit {
            true => zero(&padding).and_then(|()| {
                Ok(Self::Exit {
                    nullifier_pk,
                    asset: canonical(head)?,
                    amount,
                })
            }),
            false if nullifier_pk == ZERO => zero(slot).map(|()| Self::Dummy),
            false => Ok(Self::Ring {
                owner_key: head,
                nullifier_pk,
                recipient_u: tail,
            }),
        }
    }
}

impl AnonymousDisclosure {
    fn place(&self, fields: &mut [[u8; 32]]) -> Result<(), AuditError> {
        let layout = self.layout;
        let at = layout.fields();
        check_len(self.outputs.len(), layout.outputs)?;
        place_seed_out(fields, at.seed_out, self.seed_out)?;
        fields[at.nullifier_pks.clone()].copy_from_slice(
            &self
                .outputs
                .iter()
                .map(AnonymousOutputOpening::nullifier_pk)
                .collect::<Vec<_>>(),
        );
        let mut block = self.sender_key.to_vec();
        for output in &self.outputs {
            block.extend(output.slot_bytes()?);
        }
        fields[at.slots.clone()].copy_from_slice(&pack_disclosure(&block));
        let inputs = &mut fields[at.inputs.clone()];
        match (
            &self.inputs,
            layout.key,
            at.sender_nullifier_pk,
            &at.input_amounts,
        ) {
            (
                AnonymousInputs::Commitments(hashes),
                AnonymousAuditKey::Commitment { class },
                None,
                None,
            ) if hashes.len() == layout.inputs && layout.inputs <= class => {
                for (field, hash) in inputs.iter_mut().zip(hashes) {
                    *field = hash.unwrap_or(ZERO);
                }
            }
            (
                AnonymousInputs::Openings {
                    sender_nullifier_pk,
                    inputs: openings,
                },
                AnonymousAuditKey::Entry,
                Some(sender),
                Some(amounts),
            ) if openings.len() == layout.inputs && layout.inputs <= ANONYMOUS_ENTRY_CLASS => {
                let openings: Vec<_> = openings
                    .iter()
                    .map(|opening| opening.unwrap_or_default())
                    .collect();
                for (pair, opening) in inputs.chunks_mut(at.input_width).zip(&openings) {
                    pair.copy_from_slice(&[opening.asset, opening.blinding]);
                }
                let mut packed = vec![0; DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS];
                for (slot, opening) in packed
                    .as_chunks_mut::<DISCLOSURE_INPUT_AMOUNT_BYTES>()
                    .0
                    .iter_mut()
                    .zip(&openings)
                {
                    *slot = opening.amount.to_be_bytes();
                }
                fields[amounts.clone()].copy_from_slice(&pack_disclosure(&packed));
                fields[sender] = *sender_nullifier_pk;
            }
            _ => return Err(AuditError::DisclosureLayout),
        }
        Ok(())
    }

    fn read(
        layout: AnonymousLayout,
        exits: &[bool],
        fields: &[[u8; 32]],
    ) -> Result<Self, AuditError> {
        let at = layout.fields();
        let block = packed_bytes(
            &fields[at.slots.clone()],
            DISCLOSURE_SENDER_KEY_BYTES + ANONYMOUS_SLOT_BYTES * layout.outputs,
        )?;
        let (sender_key, slots) = block
            .split_first_chunk::<DISCLOSURE_SENDER_KEY_BYTES>()
            .ok_or(AuditError::DisclosureLayout)?;
        let outputs = fields[at.nullifier_pks.clone()]
            .iter()
            .zip(slots.as_chunks::<ANONYMOUS_SLOT_BYTES>().0)
            .zip(exits)
            .map(|((nullifier_pk, slot), exit)| {
                AnonymousOutputOpening::read(*nullifier_pk, slot, *exit)
            })
            .collect::<Result<_, _>>()?;
        let published = &fields[at.inputs.clone()];
        let inputs = match (layout.key, at.sender_nullifier_pk, &at.input_amounts) {
            (AnonymousAuditKey::Commitment { .. }, None, None) => AnonymousInputs::Commitments(
                published
                    .iter()
                    .map(|hash| (*hash != ZERO).then_some(*hash))
                    .collect(),
            ),
            (AnonymousAuditKey::Entry, Some(sender), Some(amounts)) => {
                let amounts = packed_bytes(
                    &fields[amounts.clone()],
                    DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS,
                )?;
                let (spent, unpublished) = amounts
                    .split_at_checked(DISCLOSURE_INPUT_AMOUNT_BYTES * layout.inputs)
                    .ok_or(AuditError::DisclosureLayout)?;
                zero(unpublished)?;
                AnonymousInputs::Openings {
                    sender_nullifier_pk: fields[sender],
                    inputs: spent
                        .as_chunks::<DISCLOSURE_INPUT_AMOUNT_BYTES>()
                        .0
                        .iter()
                        .zip(published.chunks(at.input_width))
                        .map(|(amount, pair)| {
                            let opening = AnonymousInputOpening {
                                asset: pair[0],
                                amount: u64::from_be_bytes(*amount),
                                blinding: pair[1],
                            };
                            (opening != AnonymousInputOpening::default()).then_some(opening)
                        })
                        .collect(),
                }
            }
            _ => return Err(AuditError::DisclosureLayout),
        };
        Ok(Self {
            layout,
            seed_out: at.seed_out.map(|index| fields[index]),
            sender_key: *sender_key,
            outputs,
            inputs,
        })
    }
}

fn packed_bytes(fields: &[[u8; 32]], len: usize) -> Result<Zeroizing<Vec<u8>>, AuditError> {
    unpack_disclosure(fields, len)
        .map(Zeroizing::new)
        .ok_or(AuditError::DisclosurePadding)
}

fn check_len(found: usize, expected: usize) -> Result<(), AuditError> {
    match found == expected {
        true => Ok(()),
        false => Err(AuditError::DisclosureLayout),
    }
}

fn place_seed_out(
    fields: &mut [[u8; 32]],
    at: Option<usize>,
    seed_out: Option<[u8; 32]>,
) -> Result<(), AuditError> {
    match (at, seed_out) {
        (Some(index), Some(seed_out)) => {
            fields[index] = seed_out;
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(AuditError::DisclosureLayout),
    }
}

fn key_and_amount(key: &[u8; 32], amount: u64) -> [u8; KEY_AND_AMOUNT_BYTES] {
    let mut bytes = [0; KEY_AND_AMOUNT_BYTES];
    let (head, tail) = bytes.split_at_mut(KEY_BYTES);
    head.copy_from_slice(key);
    tail.copy_from_slice(&amount.to_be_bytes());
    bytes
}

fn split_key_and_amount(bytes: &[u8; KEY_AND_AMOUNT_BYTES]) -> ([u8; KEY_BYTES], u64) {
    let key = core::array::from_fn(|i| bytes[i]);
    let amount = core::array::from_fn(|i| bytes[KEY_BYTES + i]);
    (key, u64::from_be_bytes(amount))
}

fn split_exit_tail(tail: &[u8; KEY_BYTES]) -> (u64, [u8; KEY_BYTES - AMOUNT_BYTES]) {
    let amount = core::array::from_fn(|i| tail[i]);
    let padding = core::array::from_fn(|i| tail[AMOUNT_BYTES + i]);
    (u64::from_be_bytes(amount), padding)
}

fn zero(bytes: &[u8]) -> Result<(), AuditError> {
    match bytes.iter().all(|byte| *byte == 0) {
        true => Ok(()),
        false => Err(AuditError::DisclosurePadding),
    }
}

pub(crate) fn canonical(field: [u8; 32]) -> Result<[u8; 32], AuditError> {
    match is_canonical_bn254_scalar_be(&field) {
        true => Ok(field),
        false => Err(AuditError::DisclosureField),
    }
}

#[cfg(test)]
mod tests;
