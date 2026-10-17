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

fn flags_field(value: u128) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

/// Reference packing bit by bit, independent of the byte-pair builder: bit `b`
/// of the element is bit `b % 8` of byte `31 - b / 8`.
fn reference_flags(allow_dummy_inputs: bool, tree_indexes: &[u8]) -> [u8; 32] {
    let mut field = [0u8; 32];
    let mut set = |bit: usize| {
        let byte = field
            .iter_mut()
            .rev()
            .nth(bit / 8)
            .expect("bit inside the element");
        *byte |= 1 << (bit % 8);
    };
    if allow_dummy_inputs {
        set(0);
    }
    for (index, tree_index) in tree_indexes.iter().enumerate() {
        for bit in 0..INPUT_FLAGS_TREE_INDEX_BITS {
            if (tree_index >> bit) & 1 == 1 {
                set(input_flags_tree_index_shift(index) + bit);
            }
        }
    }
    field
}

fn highest_set_bit(field: &[u8; 32]) -> Option<usize> {
    field
        .iter()
        .enumerate()
        .find(|(_, byte)| **byte != 0)
        .map(|(index, byte)| 8 * (field.len() - 1 - index) + 7 - byte.leading_zeros() as usize)
}

fn decimal_field(decimal: &str) -> [u8; 32] {
    let mut field = [0u8; 32];
    for digit in decimal.chars() {
        let mut carry = digit.to_digit(10).expect("decimal digit");
        for byte in field.iter_mut().rev() {
            let value = u32::from(*byte) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        assert_eq!(carry, 0, "decimal {decimal} overflows 32 bytes");
    }
    field
}

#[test]
fn input_flags_width_at_the_widest_shape_exceeds_one_u128() {
    assert_eq!(MAX_TRANSACT_INPUTS, 58);
    assert_eq!(input_flags_tree_index_shift(MAX_TRANSACT_INPUTS), 175);
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
        let packed = pack_input_flags(false, tree_indexes.iter().copied()).expect("packs");

        let shift = input_flags_tree_index_shift(index);
        assert_eq!(shift, 1 + 3 * index);
        assert_eq!(
            packed,
            reference_flags(false, &tree_indexes),
            "input {index}"
        );
        assert_eq!(highest_set_bit(&packed), Some(shift + 2), "input {index}");
    }
}

/// Input 42 occupies bits 127..=129, straddling the 128-bit boundary the
/// former `u128` builder stopped at.
#[test]
fn input_flags_carry_a_tree_index_across_the_128_bit_boundary() {
    let mut tree_indexes = vec![0u8; 43];
    *tree_indexes.last_mut().expect("43 inputs") = 3;
    let packed = pack_input_flags(true, tree_indexes.iter().copied()).expect("packs");
    assert_eq!(packed, reference_flags(true, &tree_indexes));
    let mut expected = [0u8; 32];
    *expected.get_mut(15).expect("byte 15") = 0x01;
    *expected.get_mut(16).expect("byte 16") = 0x80;
    *expected.get_mut(31).expect("byte 31") = 0x01;
    assert_eq!(packed, expected);
}

#[test]
fn input_flags_pack_every_slot_at_the_widest_shape() {
    let tree_indexes: Vec<u8> = (0..MAX_TRANSACT_INPUTS)
        .map(|index| (index % INPUT_TREES) as u8)
        .collect();
    for allow_dummy_inputs in [false, true] {
        let packed =
            pack_input_flags(allow_dummy_inputs, tree_indexes.iter().copied()).expect("packs");
        assert_eq!(packed, reference_flags(allow_dummy_inputs, &tree_indexes));
        assert!(highest_set_bit(&packed).is_some_and(|bit| (148..175).contains(&bit)));
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

/// Cross-language vectors for the packed element: the Go circuit, the Go host
/// and the TypeScript client pin the same file, so a packing change that is
/// not mirrored everywhere fails here first.
#[test]
fn input_flags_match_the_cross_language_vectors() {
    #[derive(serde::Deserialize)]
    struct InputFlagsVectors {
        input_trees: usize,
        vectors: Vec<InputFlagsVector>,
    }

    #[derive(serde::Deserialize)]
    struct InputFlagsVector {
        name: String,
        allow_dummy_inputs: bool,
        tree_indexes: Vec<u8>,
        input_flags: String,
        input_flags_decimal: String,
    }

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/input_flags.json"
    );
    let json = std::fs::read_to_string(path).expect("read test-vectors/input_flags.json");
    let pinned: InputFlagsVectors = serde_json::from_str(&json).expect("parse input_flags.json");
    assert_eq!(pinned.input_trees, INPUT_TREES);
    assert!(!pinned.vectors.is_empty());

    for vector in &pinned.vectors {
        let expected: Vec<u8> = vector
            .input_flags
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("hex digits are ascii");
                u8::from_str_radix(pair, 16).expect("hex byte")
            })
            .collect();
        let decimal = decimal_field(&vector.input_flags_decimal);

        let packed = pack_input_flags(vector.allow_dummy_inputs, vector.tree_indexes.clone())
            .unwrap_or_else(|error| panic!("vector {} failed to pack: {error:?}", vector.name));

        assert_eq!(packed.as_slice(), expected, "vector {}", vector.name);
        assert_eq!(packed, decimal, "vector {}", vector.name);
        assert_eq!(
            packed,
            reference_flags(vector.allow_dummy_inputs, &vector.tree_indexes),
            "vector {}",
            vector.name
        );
    }
}

#[test]
fn a_resolved_slot_carries_the_tree_id_and_the_roots_at_its_context() {
    use zolana_interface::{
        instruction::instruction_data::transact::TreeContext,
        state::{
            default_tree_fees, discriminator::TREE_ACCOUNT_DISCRIMINATOR, nullifier_tree_params,
        },
        tree_slot::resolve_tree_slot,
    };
    use zolana_tree::{TreeAccount, TreeError, UTXO_TREE_HEIGHT};

    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    let tree = TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        UTXO_TREE_HEIGHT as u8,
        [9u8; 32],
        0x0102,
        params,
        default_tree_fees(params.input_queue_zkp_batch_size).unwrap(),
    )
    .unwrap();
    let context = TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    };
    assert_eq!(
        resolve_tree_slot(&tree, &context),
        Ok(TreeSlot {
            id: tree_id_field(0x0102),
            utxo_root: tree.get_utxo_tree_root(0).unwrap(),
            nullifier_root: tree.get_nullifier_tree_root(0).unwrap(),
        })
    );
    let stale = TreeContext {
        nullifier_tree_root_index: 5,
        ..context
    };
    assert_eq!(
        resolve_tree_slot(&tree, &stale),
        Err(TreeError::InvalidRootIndex)
    );
}
