use super::*;
use crate::tests::support::redacts;

#[test]
fn an_anchor_prints_neither_its_slot_secret_nor_its_leaf() {
    let anchor = Anchor {
        tree_id: [1; 32],
        asset: [2; 32],
        amount: [3; 32],
        slot_secret: [0xab; 32],
        first_nullifier: [0xab; 32],
        slot_index: 0,
        epoch: 5,
        index: 6,
        path_index: 7,
        path: vec![[0xab; 32]],
    };
    let printed = format!("{anchor:?}");
    assert!(redacts(
        &printed,
        &["slot_secret", "first_nullifier", "path_index", "path"]
    ));
    assert!(!printed.contains("171, 171"));
}

#[test]
fn an_opening_or_a_merge_slot_prints_no_blinding() {
    let opening = Opening {
        blinding: [0xab; 32],
        ..Opening::default()
    };
    let slot = MergeSlot {
        domain: [1; 32],
        tree_id: [2; 32],
        amount: [3; 32],
        blinding: [0xab; 32],
        ring_data_hash: [4; 32],
    };
    for printed in [format!("{opening:?}"), format!("{slot:?}")] {
        assert!(redacts(&printed, &["blinding"]));
        assert!(!printed.contains("171, 171"));
    }
}
