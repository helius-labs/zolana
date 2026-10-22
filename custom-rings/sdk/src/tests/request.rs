use super::*;

#[test]
fn an_anchor_prints_no_slot_secret() {
    let anchor = Anchor {
        tree_id: [1; 32],
        asset: [2; 32],
        amount: [3; 32],
        slot_secret: [0xab; 32],
        first_nullifier: [4; 32],
        slot_index: 0,
        epoch: 5,
        index: 6,
        path_index: 7,
        path: vec![[8; 32]],
    };
    let printed = format!("{anchor:?}");
    assert!(printed.contains("slot_secret: \"<redacted>\"") && !printed.contains("171, 171"));
}
