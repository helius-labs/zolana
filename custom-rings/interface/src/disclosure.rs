//! Field layouts of the auditor disclosure, mirror `prover/server/custom_rings/circuits/base`.

use core::ops::Range;

use zolana_hasher::primitives::{
    is_canonical_bn254_scalar_be, pack_be_chunks, BN254_SCALAR_MODULUS_BE, PACK_BE_CHUNK_BYTES,
};

/// Capacities without a delivery proof.
pub const PACKED_AUDIT_CAPACITIES: [usize; 2] = [2, 4];
pub const DELIVERED_AUDIT_CAPACITIES: [usize; 2] = [8, 16];
/// Input slots of the widest SPP shape a compact confidential ring spend uses.
pub const CONFIDENTIAL_RING_MAX_INPUTS: usize = 48;
/// Input classes of the anonymous commitment keys per output capacity, ascending.
pub const ANONYMOUS_AUDIT_CLASSES: [(usize, &[usize]); 4] = [
    (2, &[4, 8, 12, 16, 24, 32]),
    (4, &[4, 8, 12, 16, 24]),
    (8, &[4, 8, 12, 16]),
    (16, &[1]),
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
/// The hidden sender's key ahead of the entry key's output slots.
pub const DISCLOSURE_SENDER_KEY_BYTES: usize = 32;
/// The first bytes of a spent hash a commitment key discloses.
pub const INPUT_PREFIX_BYTES: usize = 16;
/// A prefix of a canonical hash lies below `2^INPUT_PREFIX_BITS`, two prefixes pack below the modulus.
pub const INPUT_PREFIX_BITS: u32 = 126;
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
    /// Publishes spent UTXO 0's hash and the prefix of every later one, every spent UTXO a note of the ring.
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
            false => self
                .commitment_class()
                .map(|class| AnonymousAuditKey::Commitment { class }),
        }
    }

    /// The smallest commitment class holding the inputs, `None` when no key serves them.
    fn commitment_class(self) -> Option<usize> {
        ANONYMOUS_AUDIT_CLASSES
            .iter()
            .find(|(capacity, _)| *capacity == self.outputs)
            .and_then(|(_, classes)| classes.iter().copied().find(|class| *class >= self.inputs))
    }
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
    /// `nullifier_pk` per output.
    pub nullifier_pks: Range<usize>,
    /// `pack_disclosure` of `slot_bytes`, the entry key's sender key ahead of one `ANONYMOUS_SLOT_BYTES` slot per output.
    pub slots: Range<usize>,
    pub slot_bytes: usize,
    pub inputs: AnonymousInputFields,
    pub field_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnonymousInputFields {
    Commitments {
        /// Spent UTXO 0's hash.
        first: usize,
        /// [`InputPrefix::pair`] over the later published inputs.
        prefix_pairs: Range<usize>,
    },
    Openings {
        /// The `nullifier_pk` of every spent UTXO.
        sender_nullifier_pk: usize,
        /// `pack_disclosure(u64be(amount))` over the class, zero past the inputs.
        amounts: Range<usize>,
        /// `asset, blinding` per published input.
        openings: Range<usize>,
    },
}

impl AnonymousLayout {
    pub fn fields(self) -> AnonymousFields {
        let entry = self.key == AnonymousAuditKey::Entry;
        let mut next = Cursor::default();
        let seed_out = self.exits.then(|| next.one());
        let sender_nullifier_pk = entry.then(|| next.one());
        let nullifier_pks = next.run(self.outputs);
        let slot_bytes =
            usize::from(entry) * DISCLOSURE_SENDER_KEY_BYTES + ANONYMOUS_SLOT_BYTES * self.outputs;
        let slots = next.run(pack_be_chunks(slot_bytes));
        let inputs = match sender_nullifier_pk {
            Some(sender_nullifier_pk) => AnonymousInputFields::Openings {
                sender_nullifier_pk,
                amounts: next.run(pack_be_chunks(
                    DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS,
                )),
                openings: next.run(2 * self.inputs),
            },
            None => AnonymousInputFields::Commitments {
                first: next.one(),
                prefix_pairs: next.run(self.inputs / 2),
            },
        };
        AnonymousFields {
            seed_out,
            nullifier_pks,
            slots,
            slot_bytes,
            inputs,
            field_count: next.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputPrefix(u128);

impl InputPrefix {
    /// No canonical hash has a larger prefix.
    const MAX: u128 = halves(&BN254_SCALAR_MODULUS_BE)[0];
    const LOW_MASK: u128 = (1 << INPUT_PREFIX_BITS) - 1;

    /// `None` for a hash at or above the modulus or below 2^128, a zero half names no input.
    pub fn of(hash: &[u8; 32]) -> Option<Self> {
        let [prefix, _] = halves(hash);
        (is_canonical_bn254_scalar_be(hash) && prefix != 0).then_some(Self(prefix))
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    /// `first * 2^INPUT_PREFIX_BITS + second`, a `None` half is zero.
    pub fn pair(first: Option<Self>, second: Option<Self>) -> [u8; 32] {
        let [first, second] = [first, second].map(|prefix| prefix.map_or(0, Self::get));
        join([
            first >> (128 - INPUT_PREFIX_BITS),
            (first << INPUT_PREFIX_BITS) | second,
        ])
    }

    /// Inverts [`Self::pair`], `None` when a half exceeds the prefix of the modulus.
    pub fn split(field: &[u8; 32]) -> Option<[Option<Self>; 2]> {
        let [high, low] = halves(field);
        // A pair lies below 2^252.
        if high >> (2 * INPUT_PREFIX_BITS - 128) != 0 {
            return None;
        }
        let prefixes = [
            (high << (128 - INPUT_PREFIX_BITS)) | (low >> INPUT_PREFIX_BITS),
            low & Self::LOW_MASK,
        ];
        prefixes
            .iter()
            .all(|prefix| *prefix <= Self::MAX)
            .then(|| prefixes.map(|prefix| (prefix != 0).then_some(Self(prefix))))
    }
}

const fn halves(field: &[u8; 32]) -> [u128; 2] {
    let (chunks, _) = field.as_chunks::<INPUT_PREFIX_BYTES>();
    [
        u128::from_be_bytes(chunks[0]),
        u128::from_be_bytes(chunks[1]),
    ]
}

fn join(halves: [u128; 2]) -> [u8; 32] {
    let mut field = [0; 32];
    for (chunk, half) in field
        .as_chunks_mut::<INPUT_PREFIX_BYTES>()
        .0
        .iter_mut()
        .zip(halves)
    {
        *chunk = half.to_be_bytes();
    }
    field
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

    /// Every layout counts the fields of the solved Go host disclosure the vector records for it.
    #[test]
    fn field_counts_are_the_go_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/ring-disclosure-counts.json"
        ))
        .unwrap();
        let records = |kind: &str| vector[kind].as_array().unwrap().iter();
        let count = |record: &serde_json::Value, name: &str| {
            usize::try_from(record[name].as_u64().unwrap()).unwrap()
        };
        let flag = |record: &serde_json::Value, name: &str| record[name].as_bool().unwrap();
        let packed = records("packed").map(|record| {
            let layout = PackedLayout {
                outputs: count(record, "outputs"),
                exits: flag(record, "exits"),
                key_escrow: flag(record, "key_escrow"),
                data_free: flag(record, "data_free"),
            };
            (DisclosureLayout::Packed(layout), record)
        });
        let delivered = records("delivered").map(|record| {
            let layout = DeliveredLayout {
                outputs: count(record, "outputs"),
                exits: flag(record, "exits"),
                key_escrow: flag(record, "key_escrow"),
            };
            (DisclosureLayout::Delivered(layout), record)
        });
        let anonymous = records("anonymous").map(|record| {
            let key = match record["key"].as_str().unwrap() {
                "entry" => AnonymousAuditKey::Entry,
                _ => AnonymousAuditKey::Commitment {
                    class: count(record, "class"),
                },
            };
            assert_eq!(key.class(), count(record, "class"));
            let layout = AnonymousLayout {
                key,
                inputs: count(record, "inputs"),
                outputs: count(record, "outputs"),
                exits: flag(record, "exits"),
            };
            (DisclosureLayout::Anonymous(layout), record)
        });
        for (layout, record) in packed.chain(delivered).chain(anonymous) {
            assert_eq!(layout.field_count(), count(record, "fields"), "{record}");
        }
    }

    /// No canonical hash has a prefix above the modulus prefix, two prefixes pack below 2^252 and split back.
    #[test]
    fn input_prefixes_pack_two_to_a_field_and_split_back() {
        let mut below = BN254_SCALAR_MODULUS_BE;
        below[31] -= 1;
        let top = InputPrefix::of(&below).unwrap();
        assert_eq!(top.get(), InputPrefix::MAX);
        assert_eq!(InputPrefix::of(&BN254_SCALAR_MODULUS_BE), None);
        let mut short = [0; 32];
        short[16] = 1;
        assert_eq!(InputPrefix::of(&short), None);
        let low = InputPrefix::of(&[0x01; 32]).unwrap();
        for pair in [
            [Some(top), Some(top)],
            [Some(low), None],
            [None, Some(top)],
            [None, None],
        ] {
            let field = InputPrefix::pair(pair[0], pair[1]);
            assert!(is_canonical_bn254_scalar_be(&field));
            assert_eq!(InputPrefix::split(&field), Some(pair));
        }
        let mut over = InputPrefix::pair(None, Some(top));
        over[31] += 1;
        assert_eq!(InputPrefix::split(&over), None);
        let mut wide = [0; 32];
        wide[0] = 0x10;
        assert_eq!(InputPrefix::split(&wide), None);
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
        assert_eq!(key(25, 2, false), commitment(32));
        assert_eq!(key(32, 2, false), commitment(32));
        assert_eq!(key(33, 2, false), None);
        assert_eq!(key(25, 4, false), None);
        assert_eq!(key(9, 8, false), commitment(12));
        assert_eq!(key(17, 8, false), None);
        assert_eq!(key(1, 16, false), commitment(1));
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
