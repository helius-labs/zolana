extern crate alloc;

use proptest::prelude::*;
use spr_circuit::protocol::{SpentInput, UtxoMeta};
use spr_circuit::{Field, to_bytes};

#[path = "../src/protocol/input_order.rs"]
mod input_order;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn ordering_is_a_stable_partition_and_preserves_every_input(dummy in prop::collection::vec(any::<bool>(), 0..21)) {
        let inputs: Vec<_> = dummy.iter().enumerate().map(|(index, dummy)| (SpentInput {
            hash: Field::from(index as u64 + 1),
            meta: UtxoMeta { nullifier: Field::from(index as u64 + 101), latest_tree_id: index as u16,
                has_latest_tree_id: index % 2 == 0 },
        }, *dummy)).collect();
        let expected: Vec<_> = inputs.iter().filter(|(_, dummy)| !dummy)
            .chain(inputs.iter().filter(|(_, dummy)| *dummy)).map(|(input, _)| encode(input)).collect();
        let ordered = input_order::ordered_inputs(inputs);
        prop_assert_eq!(ordered.iter().map(encode).collect::<Vec<_>>(), expected);
    }
}

fn encode(input: &SpentInput) -> ([u8; 32], [u8; 32], u16, bool) {
    (
        to_bytes(&input.hash),
        to_bytes(&input.meta.nullifier),
        input.meta.latest_tree_id,
        input.meta.has_latest_tree_id,
    )
}
