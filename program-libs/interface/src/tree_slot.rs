//! Tree slots: the public-input element that commits a spend proof to the
//! trees its inputs may come from. Mirrors Go
//! `circuits/spp_transaction/shared/tree_slot.go` and the host mirror
//! `prover-test/spp/protocol/tree_slot.go`; the program and the client share
//! this one implementation.
//!
//! A proof publishes [`INPUT_TREES`] slots `(id, utxo_root, nullifier_root)`.
//! Each input selects its slot privately, so a UTXO cannot be hashed under one
//! tree and proven against another's roots. Populated slots come first;
//! unused slots are all zero and sit at the end, so their suffix of the
//! right-folded chain is a constant ([`ZERO_TREE_SLOT_SUFFIX_CHAINS`]). A
//! spend populates one slot per input tree it declares, in account order, and
//! starts the chain from the zero suffix of the unused remainder.

use zolana_hasher::{
    hash_chain::create_right_hash_chain_from_slice, primitives::right_align, Hasher, HasherError,
    Poseidon,
};

use crate::{error::ShieldedPoolError, INPUT_TREES, MAX_TRANSACT_INPUTS};

/// One tree slot: the raw `u16` tree id as a field element and the two roots
/// SPP resolved for that tree. An unused slot is all zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreeSlot {
    pub id: [u8; 32],
    pub utxo_root: [u8; 32],
    pub nullifier_root: [u8; 32],
}

impl TreeSlot {
    /// An unused slot. The circuit rejects selecting it because both roots are
    /// zero.
    pub const ZERO: Self = Self {
        id: [0u8; 32],
        utxo_root: [0u8; 32],
        nullifier_root: [0u8; 32],
    };

    pub fn new(tree_id: u16, utxo_root: [u8; 32], nullifier_root: [u8; 32]) -> Self {
        Self {
            id: tree_id_field(tree_id),
            utxo_root,
            nullifier_root,
        }
    }

    /// `Poseidon(id, utxo_root, nullifier_root)`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[&self.id, &self.utxo_root, &self.nullifier_root])
    }
}

/// The field element of a raw `u16` tree id: right-aligned big-endian.
pub fn tree_id_field(tree_id: u16) -> [u8; 32] {
    right_align(&tree_id.to_be_bytes())
}

/// Bits one input's tree index occupies in the packed `input_flags` element.
pub const INPUT_FLAGS_TREE_INDEX_BITS: usize = 3;

/// Bit position of input `index`'s tree index in `input_flags`. Bit 0 is the
/// dummy-input policy, so input `i` occupies bits `1 + 3i ..= 3 + 3i`.
pub const fn input_flags_tree_index_shift(index: usize) -> usize {
    1 + INPUT_FLAGS_TREE_INDEX_BITS * index
}

/// Three bits hold every valid tree index.
const _: () = assert!(INPUT_TREES <= 1 << INPUT_FLAGS_TREE_INDEX_BITS);
/// The packed element is built in a single `u128` limb; a wider shape would
/// need a two-limb builder in every mirror.
const _: () = assert!(input_flags_tree_index_shift(MAX_TRANSACT_INPUTS) <= 128);

/// Pack the transaction's dummy-input policy and every input's tree index into
/// the single `input_flags` public-input element (spec: `transact`
/// `input_flags`). Mirrored by the Go circuit, the Go host and the TypeScript
/// client, so the layout is fixed:
///
/// ```text
/// input_flags = allow_dummy_inputs                       (bit 0)
///             | tree_index[i] << (1 + 3 * i)   for each input i
/// ```
///
/// The value is built as a big-endian `u128` and right-aligned into a
/// 32-byte field element. `tree_indexes` is the inputs' `tree_index` in input
/// order; the circuit decodes exactly `1 + 3 * n_inputs` bits, so an index
/// outside `0..INPUT_TREES` or an input count above [`MAX_TRANSACT_INPUTS`]
/// is rejected here rather than silently aliasing another input's bits.
pub fn pack_input_flags(
    allow_dummy_inputs: bool,
    tree_indexes: impl IntoIterator<Item = u8>,
) -> Result<[u8; 32], ShieldedPoolError> {
    let mut flags = u128::from(allow_dummy_inputs);
    for (index, tree_index) in tree_indexes.into_iter().enumerate() {
        if index >= MAX_TRANSACT_INPUTS {
            return Err(ShieldedPoolError::InvalidTransactShape);
        }
        if usize::from(tree_index) >= INPUT_TREES {
            return Err(ShieldedPoolError::InputTreeIndexOutOfRange);
        }
        flags |= u128::from(tree_index) << input_flags_tree_index_shift(index);
    }
    Ok(right_align(&flags.to_be_bytes()))
}

/// Right-folds every slot's [`TreeSlot::hash`]:
/// `h = hash_4; for k in (0..4).rev() { h = Poseidon(hash_k, h) }`.
pub fn tree_slots_hash_chain(slots: &[TreeSlot; INPUT_TREES]) -> Result<[u8; 32], HasherError> {
    let mut hashes = [[0u8; 32]; INPUT_TREES];
    for (hash, slot) in hashes.iter_mut().zip(slots) {
        *hash = slot.hash()?;
    }
    create_right_hash_chain_from_slice(&hashes)
}

/// Right hash chain over `m` all-zero slots, at index `m - 1`:
/// `S(1) = Z`, `S(m) = Poseidon(Z, S(m - 1))` with `Z = Poseidon(0, 0, 0)`.
/// Pinned by `zero_suffix_chains_match_recomputation`.
pub static ZERO_TREE_SLOT_SUFFIX_CHAINS: [[u8; 32]; INPUT_TREES - 1] = [
    [
        0x0b, 0xc1, 0x88, 0xd2, 0x7d, 0xcc, 0xea, 0xdc, 0x1d, 0xcf, 0xb6, 0xaf, 0x0a, 0x7a, 0xf0,
        0x8f, 0xe2, 0x86, 0x4e, 0xec, 0xec, 0x96, 0xc5, 0xae, 0x7c, 0xee, 0x6d, 0xb3, 0x1b, 0xa5,
        0x99, 0xaa,
    ],
    [
        0x0b, 0xb8, 0xc4, 0xe7, 0x9b, 0x87, 0xe2, 0x19, 0x62, 0xd4, 0x96, 0xcf, 0xc7, 0xbb, 0xe6,
        0x72, 0x6a, 0x8d, 0x1a, 0xb8, 0xed, 0x98, 0x74, 0x16, 0xde, 0x3c, 0x54, 0x33, 0x3b, 0x1f,
        0x65, 0x1e,
    ],
    [
        0x0d, 0x99, 0x66, 0x90, 0xab, 0xbd, 0xa0, 0xb8, 0xaa, 0xc1, 0x06, 0xd1, 0x5f, 0xa1, 0xc0,
        0xf1, 0xe3, 0x98, 0x10, 0xee, 0x2b, 0x90, 0xed, 0x59, 0x11, 0xb7, 0x96, 0xfc, 0x2b, 0x23,
        0xee, 0xdb,
    ],
    [
        0x0b, 0x62, 0x21, 0x6e, 0x4d, 0xd6, 0xdb, 0x08, 0xea, 0x73, 0xf2, 0x9c, 0xf0, 0x70, 0xf7,
        0xa7, 0x8a, 0xf9, 0x14, 0x17, 0x39, 0x5f, 0x45, 0xbc, 0x7e, 0xc9, 0x8e, 0x5a, 0x4d, 0x93,
        0x46, 0x41,
    ],
];

/// [`tree_slots_hash_chain`] over `populated` followed by all-zero slots up to
/// [`INPUT_TREES`], hashing only the populated slots: the chain starts from the
/// precomputed zero suffix for the unused count and folds the populated hashes
/// from the right. `populated` must hold 1..=`INPUT_TREES` slots.
pub fn populated_tree_slots_hash_chain(populated: &[TreeSlot]) -> Result<[u8; 32], HasherError> {
    let count = populated.len();
    if count == 0 || count > INPUT_TREES {
        return Err(HasherError::InvalidInputLength(count, INPUT_TREES));
    }
    let unused = INPUT_TREES - count;
    let (mut chain, prefix) = match unused
        .checked_sub(1)
        .and_then(|index| ZERO_TREE_SLOT_SUFFIX_CHAINS.get(index))
    {
        Some(suffix) => (*suffix, populated),
        None => {
            let (last, prefix) = populated
                .split_last()
                .ok_or(HasherError::InvalidInputLength(count, INPUT_TREES))?;
            (last.hash()?, prefix)
        }
    };
    for slot in prefix.iter().rev() {
        chain = Poseidon::hashv(&[&slot.hash()?, &chain])?;
    }
    Ok(chain)
}
