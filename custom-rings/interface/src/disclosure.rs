//! Field layouts of the auditor disclosure, mirror `prover/server/custom_rings/circuits/base`.

use core::ops::Range;

use zolana_hasher::primitives::{pack_be_chunks, PACK_BE_CHUNK_BYTES};

/// Capacities without a delivery proof.
pub const PACKED_AUDIT_CAPACITIES: [usize; 2] = [2, 4];
pub const DELIVERED_AUDIT_CAPACITIES: [usize; 2] = [8, 16];
/// Input classes of the anonymous commitment keys per output capacity, ascending.
pub const ANONYMOUS_AUDIT_CLASSES: [(usize, &[usize]); 3] = [
    (2, &[4, 8, 12, 16, 24, 28]),
    (4, &[4, 8, 12, 16, 24]),
    (8, &[4, 8, 12, 16]),
];
/// Input slots of every anonymous entry key.
pub const ANONYMOUS_ENTRY_CLASS: usize = 8;
pub const ANONYMOUS_ENTRY_OUTPUTS: [usize; 3] = [2, 4, 8];
/// A delivered slot of a transfer with an exit, ring `owner_key || 0^8`, exit `asset || u64be(amount)`.
pub const DELIVERED_SLOT_BYTES: usize = 40;
/// A delivered ring slot of an exit-free transfer, `owner_key`.
pub const DENSE_DELIVERED_SLOT_BYTES: usize = 32;
/// A ring slot `owner_key || u`, an exit `asset || u64be(amount) || 0^24`.
pub const ANONYMOUS_SLOT_BYTES: usize = 64;
/// The hidden sender's key ahead of the anonymous output slots.
pub const DISCLOSURE_SENDER_KEY_BYTES: usize = 32;
/// One `u64be(amount)` per input slot of the entry class.
pub const DISCLOSURE_INPUT_AMOUNT_BYTES: usize = 8;
/// `pack_disclosure(owner_key || u64be(amount))` closing every packed slot.
const PACKED_OWNER_AND_AMOUNT_FIELDS: usize = pack_be_chunks(32 + 8);

/// The audit statement's layout element, mirror `prover/server/custom_rings/circuits/base/layout.go`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditLayout {
    /// A published output exits, `SeedOut` opens the disclosure.
    pub exits: bool,
    /// The policy proof escrows every output nullifier key the disclosure leaves out.
    pub key_escrow: bool,
    /// No published output carries a data hash.
    pub data_free: bool,
    /// The anonymous entry key, every spent UTXO opens in full.
    pub full_openings: bool,
}

impl AuditLayout {
    pub const fn value(self) -> u8 {
        self.exits as u8
            | (self.key_escrow as u8) << 1
            | (self.data_free as u8) << 2
            | (self.full_openings as u8) << 3
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousAuditKey {
    /// Publishes each spent UTXO's hash, every spent UTXO a note of the ring.
    Commitment { class: usize },
    /// Opens every spent UTXO, the key of a transfer that spends a default-ring note.
    Entry,
}

impl AnonymousAuditKey {
    pub const fn class(self) -> usize {
        match self {
            Self::Commitment { class } => class,
            Self::Entry => ANONYMOUS_ENTRY_CLASS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousSpend {
    /// Published inputs.
    pub inputs: usize,
    pub outputs: usize,
    /// A spent UTXO is a default-ring note, the commitment keys refuse ring id zero.
    pub spends_default_ring: bool,
}

impl AnonymousSpend {
    /// `None` when no key serves the spend, a larger entry spend splits.
    pub fn audit_key(self) -> Option<AnonymousAuditKey> {
        match self.spends_default_ring {
            true => (ANONYMOUS_ENTRY_OUTPUTS.contains(&self.outputs)
                && self.inputs <= ANONYMOUS_ENTRY_CLASS)
                .then_some(AnonymousAuditKey::Entry),
            false => anonymous_audit_class(self.inputs, self.outputs)
                .map(|class| AnonymousAuditKey::Commitment { class }),
        }
    }
}

/// The smallest commitment class holding `inputs` for `outputs`, `None` when no key serves it.
pub fn anonymous_audit_class(inputs: usize, outputs: usize) -> Option<usize> {
    ANONYMOUS_AUDIT_CLASSES
        .iter()
        .find(|(capacity, _)| *capacity == outputs)
        .and_then(|(_, classes)| classes.iter().copied().find(|class| *class >= inputs))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisclosureLayout {
    /// Capacity 2 and 4 of the confidential and delegate rails.
    Packed(PackedLayout),
    /// Capacity 8 and 16 of the confidential and delegate rails.
    Delivered(DeliveredLayout),
    Anonymous(AnonymousLayout),
}

impl DisclosureLayout {
    pub fn field_count(self) -> usize {
        match self {
            Self::Packed(layout) => layout.fields().field_count,
            Self::Delivered(layout) => layout.fields().field_count,
            Self::Anonymous(layout) => layout.fields().field_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedLayout {
    /// The published slots, a prefix of the capacity.
    pub outputs: usize,
    pub exits: bool,
    pub key_escrow: bool,
    pub data_free: bool,
}

/// Positions in a packed disclosure, slot `k` opens at `first_slot + k * slot_width`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedFields {
    pub seed_out: Option<usize>,
    pub first_slot: usize,
    pub slot_width: usize,
    /// Offsets inside a slot from here on.
    pub nullifier_pk: Option<usize>,
    pub asset: usize,
    /// `data_hash` then `ring_data_hash`.
    pub data_hashes: Option<usize>,
    /// The two fields of `pack_disclosure(owner_key || u64be(amount))`.
    pub owner_and_amount: usize,
    pub field_count: usize,
}

impl PackedLayout {
    pub fn fields(self) -> PackedFields {
        let mut next = Cursor::default();
        let seed_out = self.exits.then(|| next.one());
        let mut slot = Cursor::default();
        let nullifier_pk = (!self.key_escrow).then(|| slot.one());
        let asset = slot.one();
        let data_hashes = (!self.data_free).then(|| slot.run(2).start);
        let owner_and_amount = slot.run(PACKED_OWNER_AND_AMOUNT_FIELDS).start;
        let first_slot = next.run(self.outputs * slot.0).start;
        PackedFields {
            seed_out,
            first_slot,
            slot_width: slot.0,
            nullifier_pk,
            asset,
            data_hashes,
            owner_and_amount,
            field_count: next.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveredLayout {
    /// Every slot of the capacity.
    pub outputs: usize,
    pub exits: bool,
    pub key_escrow: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveredFields {
    pub seed_out: Option<usize>,
    /// `nullifier_pk` per slot.
    pub nullifier_pks: Option<Range<usize>>,
    /// `pack_disclosure` of every slot, `slot_bytes` each.
    pub slots: Range<usize>,
    pub slot_bytes: usize,
    pub field_count: usize,
}

impl DeliveredLayout {
    pub fn fields(self) -> DeliveredFields {
        let mut next = Cursor::default();
        let seed_out = self.exits.then(|| next.one());
        let nullifier_pks = (!self.key_escrow).then(|| next.run(self.outputs));
        let slot_bytes = match self.exits {
            true => DELIVERED_SLOT_BYTES,
            false => DENSE_DELIVERED_SLOT_BYTES,
        };
        let slots = next.run(pack_be_chunks(slot_bytes * self.outputs));
        DeliveredFields {
            seed_out,
            nullifier_pks,
            slots,
            slot_bytes,
            field_count: next.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousLayout {
    pub key: AnonymousAuditKey,
    /// Published inputs.
    pub inputs: usize,
    pub outputs: usize,
    pub exits: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousFields {
    pub seed_out: Option<usize>,
    /// The entry key's `nullifier_pk` of every spent UTXO.
    pub sender_nullifier_pk: Option<usize>,
    /// `nullifier_pk` per output.
    pub nullifier_pks: Range<usize>,
    /// `pack_disclosure(sender_key || slots)`, `ANONYMOUS_SLOT_BYTES` a slot.
    pub slots: Range<usize>,
    /// The entry key's `pack_disclosure(u64be(amount))` over its class, zero past the inputs.
    pub input_amounts: Option<Range<usize>>,
    /// Per published input `input_width` fields, the UTXO hash or the entry key's `asset, blinding`.
    pub inputs: Range<usize>,
    pub input_width: usize,
    pub field_count: usize,
}

impl AnonymousLayout {
    pub fn fields(self) -> AnonymousFields {
        let entry = self.key == AnonymousAuditKey::Entry;
        let mut next = Cursor::default();
        let seed_out = self.exits.then(|| next.one());
        let sender_nullifier_pk = entry.then(|| next.one());
        let nullifier_pks = next.run(self.outputs);
        let slots = next.run(pack_be_chunks(
            DISCLOSURE_SENDER_KEY_BYTES + ANONYMOUS_SLOT_BYTES * self.outputs,
        ));
        let input_amounts = entry.then(|| {
            next.run(pack_be_chunks(
                DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS,
            ))
        });
        let input_width = 1 + usize::from(entry);
        let inputs = next.run(input_width * self.inputs);
        AnonymousFields {
            seed_out,
            sender_nullifier_pk,
            nullifier_pks,
            slots,
            input_amounts,
            inputs,
            input_width,
            field_count: next.0,
        }
    }
}

#[derive(Default)]
struct Cursor(usize);

impl Cursor {
    fn one(&mut self) -> usize {
        self.run(1).start
    }

    fn run(&mut self, len: usize) -> Range<usize> {
        let start = self.0;
        self.0 += len;
        start..self.0
    }
}

/// Zero pads the plaintext at its end to whole 31-byte chunks, one chunk per field.
pub fn pack_disclosure(plaintext: &[u8]) -> Vec<[u8; 32]> {
    plaintext
        .chunks(PACK_BE_CHUNK_BYTES)
        .map(|chunk| {
            let mut field = [0u8; 32];
            field[1..1 + chunk.len()].copy_from_slice(chunk);
            field
        })
        .collect()
}

/// Inverts [`pack_disclosure`], `None` when a field holds bytes outside its chunk.
pub fn unpack_disclosure(fields: &[[u8; 32]], len: usize) -> Option<Vec<u8>> {
    if fields.len() != pack_be_chunks(len) {
        return None;
    }
    let mut plaintext = Vec::with_capacity(len);
    for (index, field) in fields.iter().enumerate() {
        let chunk = (len - index * PACK_BE_CHUNK_BYTES).min(PACK_BE_CHUNK_BYTES);
        let (bytes, padding) = field[1..].split_at(chunk);
        if field[0] != 0 || padding.iter().any(|byte| *byte != 0) {
            return None;
        }
        plaintext.extend_from_slice(bytes);
    }
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed(outputs: usize, exits: bool, key_escrow: bool, data_free: bool) -> usize {
        DisclosureLayout::Packed(PackedLayout {
            outputs,
            exits,
            key_escrow,
            data_free,
        })
        .field_count()
    }

    fn delivered(outputs: usize, exits: bool, key_escrow: bool) -> usize {
        DisclosureLayout::Delivered(DeliveredLayout {
            outputs,
            exits,
            key_escrow,
        })
        .field_count()
    }

    fn anonymous(key: AnonymousAuditKey, outputs: usize, exits: bool) -> usize {
        DisclosureLayout::Anonymous(AnonymousLayout {
            key,
            inputs: 2,
            outputs,
            exits,
        })
        .field_count()
    }

    #[test]
    fn field_counts_match_the_go_host_checks() {
        assert_eq!(packed(3, true, false, false), 19);
        assert_eq!(packed(3, false, false, false), 18);
        assert_eq!(packed(3, true, true, false), 16);
        assert_eq!(packed(3, false, true, true), 9);
        assert_eq!(
            [(true, false), (false, false), (true, true), (false, true)]
                .map(|(exits, escrow)| [8, 16].map(|m| delivered(m, exits, escrow))),
            [[20, 38], [17, 33], [12, 22], [9, 17]]
        );
        let commitment = AnonymousAuditKey::Commitment { class: 4 };
        assert_eq!(anonymous(commitment, 2, false), 10);
        assert_eq!(anonymous(commitment, 4, true), 17);
        assert_eq!(anonymous(commitment, 8, true), 29);
        assert_eq!(anonymous(AnonymousAuditKey::Entry, 2, false), 16);
        assert_eq!(anonymous(AnonymousAuditKey::Entry, 4, true), 23);
        assert_eq!(anonymous(AnonymousAuditKey::Entry, 8, true), 35);
    }

    #[test]
    fn positions_skip_every_field_the_flags_leave_out() {
        let full = PackedLayout {
            outputs: 2,
            exits: true,
            key_escrow: false,
            data_free: false,
        }
        .fields();
        assert_eq!(
            (full.seed_out, full.first_slot, full.slot_width),
            (Some(0), 1, 6)
        );
        assert_eq!(
            (
                full.nullifier_pk,
                full.asset,
                full.data_hashes,
                full.owner_and_amount
            ),
            (Some(0), 1, Some(2), 4)
        );
        let lean = PackedLayout {
            outputs: 2,
            exits: false,
            key_escrow: true,
            data_free: true,
        }
        .fields();
        assert_eq!(
            (
                lean.seed_out,
                lean.first_slot,
                lean.slot_width,
                lean.nullifier_pk
            ),
            (None, 0, 3, None)
        );
        assert_eq!(
            (lean.asset, lean.data_hashes, lean.owner_and_amount),
            (0, None, 1)
        );
        let dense = DeliveredLayout {
            outputs: 8,
            exits: false,
            key_escrow: false,
        }
        .fields();
        assert_eq!((dense.seed_out, dense.nullifier_pks), (None, Some(0..8)));
        assert_eq!((dense.slots, dense.slot_bytes), (8..17, 32));
        let entry = AnonymousLayout {
            key: AnonymousAuditKey::Entry,
            inputs: 3,
            outputs: 2,
            exits: true,
        }
        .fields();
        assert_eq!(
            (entry.seed_out, entry.sender_nullifier_pk),
            (Some(0), Some(1))
        );
        assert_eq!((entry.nullifier_pks, entry.slots), (2..4, 4..10));
        assert_eq!((entry.input_amounts, entry.inputs), (Some(10..13), 13..19));
        let commitment = AnonymousLayout {
            key: AnonymousAuditKey::Commitment { class: 4 },
            inputs: 3,
            outputs: 2,
            exits: true,
        }
        .fields();
        assert_eq!(
            (commitment.sender_nullifier_pk, commitment.input_amounts),
            (None, None)
        );
        assert_eq!((commitment.inputs, commitment.input_width), (9..12, 1));
    }

    #[test]
    fn the_layout_value_packs_its_flags_from_the_low_bit() {
        let flags = |exits, key_escrow, data_free, full_openings| {
            AuditLayout {
                exits,
                key_escrow,
                data_free,
                full_openings,
            }
            .value()
        };
        assert_eq!(flags(true, false, false, false), 1);
        assert_eq!(flags(false, true, false, false), 2);
        assert_eq!(flags(false, false, true, false), 4);
        assert_eq!(flags(false, false, false, true), 8);
        assert_eq!(flags(true, true, true, true), 15);
    }

    #[test]
    fn a_commitment_spend_takes_the_smallest_class_and_an_entry_spend_its_one_key() {
        let key = |inputs, outputs, spends_default_ring| {
            AnonymousSpend {
                inputs,
                outputs,
                spends_default_ring,
            }
            .audit_key()
        };
        let commitment = |class| Some(AnonymousAuditKey::Commitment { class });
        assert_eq!(key(1, 2, false), commitment(4));
        assert_eq!(key(17, 2, false), commitment(24));
        assert_eq!(key(28, 2, false), commitment(28));
        assert_eq!(key(29, 2, false), None);
        assert_eq!(key(25, 4, false), None);
        assert_eq!(key(9, 8, false), commitment(12));
        assert_eq!(key(17, 8, false), None);
        assert_eq!(key(2, 16, false), None);
        assert_eq!(key(1, 2, true), Some(AnonymousAuditKey::Entry));
        assert_eq!(key(8, 8, true), Some(AnonymousAuditKey::Entry));
        assert_eq!(key(9, 4, true), None);
        assert_eq!(key(2, 16, true), None);
    }

    #[test]
    fn a_short_tail_chunk_is_left_aligned_and_zero_padded() {
        let plaintext: Vec<u8> = (1..=40).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0][0], 0);
        assert_eq!(fields[0][1..], plaintext[..31]);
        assert_eq!(fields[1][..10], [0, 32, 33, 34, 35, 36, 37, 38, 39, 40]);
        assert_eq!(fields[1][10..], [0u8; 22]);
        assert_eq!(
            unpack_disclosure(&fields, 40).as_deref(),
            Some(&plaintext[..])
        );
    }

    #[test]
    fn unpacking_rejects_bytes_outside_a_chunk() {
        let plaintext: Vec<u8> = (1..=70).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 3);
        assert_eq!(unpack_disclosure(&fields, 94), None);
        let mut padded = fields.clone();
        padded[2][9] = 1;
        assert_eq!(unpack_disclosure(&padded, 70), None);
        let mut widened = fields;
        widened[0][0] = 1;
        assert_eq!(unpack_disclosure(&widened, 70), None);
    }
}
