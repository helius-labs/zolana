use zolana_hasher::{Hasher, HasherError, Poseidon};
use zolana_interface::{
    tree_slot::{
        populated_tree_slots_hash_chain, tree_id_field, tree_slots_hash_chain, TreeSlot,
        ZERO_TREE_SLOT_SUFFIX_CHAINS,
    },
    INPUT_TREES,
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
