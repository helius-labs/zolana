use zolana_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    tree_slot::{
        input_flags_tree_index_shift, pack_input_flags, populated_tree_slots_hash_chain,
        tree_id_field, tree_slots_hash_chain, TreeSlot, INPUT_FLAGS_TREE_INDEX_BITS,
        ZERO_TREE_SLOT_SUFFIX_CHAINS,
    },
    INPUT_TREES, MAX_TRANSACT_INPUTS,
};

fn slot(seed: u8) -> TreeSlot {
    TreeSlot::new(
        u16::from(seed),
        core::array::from_fn(|i| seed.wrapping_add(i as u8)),
        core::array::from_fn(|i| seed.wrapping_mul(3).wrapping_add(i as u8)),
    )
}

#[test]
fn tree_id_field_is_right_aligned_big_endian() {
    let mut expected = [0u8; 32];
    expected[30] = 0x12;
    expected[31] = 0x34;
    assert_eq!(tree_id_field(0x1234), expected);
    assert_eq!(tree_id_field(0), [0u8; 32]);
    assert_eq!(TreeSlot::new(0, [0u8; 32], [0u8; 32]), TreeSlot::ZERO);
}

#[test]
fn zero_suffix_chains_match_recomputation() {
    let zero = TreeSlot::ZERO.hash().unwrap();
    let zero_field = [0u8; 32];
    assert_eq!(
        zero,
        Poseidon::hashv(&[&zero_field, &zero_field, &zero_field]).unwrap()
    );
    let mut expected = [[0u8; 32]; INPUT_TREES - 1];
    let mut chain = zero;
    for suffix in expected.iter_mut() {
        *suffix = chain;
        chain = Poseidon::hashv(&[&zero, &chain]).unwrap();
    }
    assert_eq!(
        ZERO_TREE_SLOT_SUFFIX_CHAINS, expected,
        "expected {expected:02x?}"
    );
}

#[test]
fn populated_chain_matches_the_generic_chain_for_every_count() {
    let slots: [TreeSlot; INPUT_TREES] = core::array::from_fn(|k| slot(10 + k as u8));
    for count in 1..=INPUT_TREES {
        let mut padded = [TreeSlot::ZERO; INPUT_TREES];
        padded[..count].copy_from_slice(&slots[..count]);
        assert_eq!(
            populated_tree_slots_hash_chain(&slots[..count]).unwrap(),
            tree_slots_hash_chain(&padded).unwrap(),
            "count {count}"
        );
    }
}

#[test]
fn generic_chain_is_a_right_fold_over_slot_hashes() {
    let slots: [TreeSlot; INPUT_TREES] = core::array::from_fn(|k| slot(1 + k as u8));
    let mut expected = slots[INPUT_TREES - 1].hash().unwrap();
    for slot in slots[..INPUT_TREES - 1].iter().rev() {
        expected = Poseidon::hashv(&[&slot.hash().unwrap(), &expected]).unwrap();
    }
    assert_eq!(tree_slots_hash_chain(&slots).unwrap(), expected);
}

#[test]
fn populated_chain_rejects_empty_and_oversized_input() {
    assert_eq!(
        populated_tree_slots_hash_chain(&[]),
        Err(HasherError::InvalidInputLength(0, INPUT_TREES))
    );
    let too_many = [slot(1); INPUT_TREES + 1];
    assert_eq!(
        populated_tree_slots_hash_chain(&too_many),
        Err(HasherError::InvalidInputLength(
            INPUT_TREES + 1,
            INPUT_TREES
        ))
    );
}

/// The packed element must fit one `u128` limb in every mirror; the same bound
/// is pinned as a `const` assertion next to `pack_input_flags`.
const _: () = assert!(input_flags_tree_index_shift(MAX_TRANSACT_INPUTS) <= 128);

fn flags_field(value: u128) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

#[test]
fn input_flags_bit_zero_is_the_dummy_policy() {
    assert_eq!(pack_input_flags(false, []), Ok(flags_field(0)));
    assert_eq!(pack_input_flags(true, []), Ok(flags_field(1)));
    assert_eq!(pack_input_flags(false, [0]), Ok(flags_field(0)));
    assert_eq!(pack_input_flags(true, [0]), Ok(flags_field(1)));
}

#[test]
fn input_flags_place_one_input_in_its_own_three_bit_field() {
    for tree_index in 0..INPUT_TREES as u8 {
        assert_eq!(
            pack_input_flags(false, [tree_index]),
            Ok(flags_field(u128::from(tree_index) << 1))
        );
        assert_eq!(
            pack_input_flags(true, [tree_index]),
            Ok(flags_field(1 | (u128::from(tree_index) << 1)))
        );
    }
}

#[test]
fn input_flags_give_input_i_bits_1_plus_3i_through_3_plus_3i() {
    let highest = (INPUT_TREES - 1) as u8;
    for index in 0..MAX_TRANSACT_INPUTS {
        let mut tree_indexes = vec![0u8; MAX_TRANSACT_INPUTS];
        *tree_indexes.get_mut(index).expect("index in range") = highest;
        let packed = pack_input_flags(false, tree_indexes).expect("packs");

        let shift = input_flags_tree_index_shift(index);
        assert_eq!(shift, 1 + 3 * index);
        assert_eq!(packed, flags_field(u128::from(highest) << shift));

        let occupied = ((1u128 << INPUT_FLAGS_TREE_INDEX_BITS) - 1) << shift;
        let value = u128::from_be_bytes(
            packed[16..]
                .try_into()
                .expect("packed flags fit the low 16 bytes"),
        );
        assert_eq!(packed[..16], [0u8; 16]);
        assert_eq!(value & !occupied, 0);
    }
}

#[test]
fn input_flags_pack_every_input_without_overlap() {
    let tree_indexes = [1u8, 2, 3, 4];
    let expected = (1 << 1) | (2 << 4) | (3 << 7) | (4u128 << 10);
    assert_eq!(
        pack_input_flags(false, tree_indexes),
        Ok(flags_field(expected))
    );
    assert_eq!(
        pack_input_flags(true, tree_indexes),
        Ok(flags_field(expected | 1))
    );
}

#[test]
fn input_flags_reject_out_of_range_indexes_and_oversized_shapes() {
    assert_eq!(
        pack_input_flags(false, [INPUT_TREES as u8]),
        Err(ShieldedPoolError::InputTreeIndexOutOfRange)
    );
    assert_eq!(
        pack_input_flags(false, [0, 7]),
        Err(ShieldedPoolError::InputTreeIndexOutOfRange)
    );
    assert_eq!(
        pack_input_flags(false, [0u8; MAX_TRANSACT_INPUTS]),
        Ok(flags_field(0))
    );
    assert_eq!(
        pack_input_flags(false, vec![0u8; MAX_TRANSACT_INPUTS + 1]),
        Err(ShieldedPoolError::InvalidTransactShape)
    );
}
