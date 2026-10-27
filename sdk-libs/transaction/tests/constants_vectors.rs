use serde_json::Value;
use spr_interface::instruction::tag;
use spr_interface::state::tree::{NULLIFIER_TREE_HEIGHT, STATE_HEIGHT};
use spr_interface::{INPUT_TREES, MAX_INPUT_TREES};
use spr_keypair::constants::VIEW_TAG_LEN;
use spr_transaction::instructions::{merge::MERGE_DEFAULT_INPUT_COUNT, transact::MAX_SPEND_INPUTS};

#[test]
fn constants_match_the_shared_vector() {
    let vector: Value =
        serde_json::from_str(include_str!("../../../test-vectors/constants.json")).unwrap();
    assert_eq!(vector["mergeInputs"], MERGE_DEFAULT_INPUT_COUNT as u64);
    assert_eq!(vector["stateTreeHeight"], STATE_HEIGHT as u64);
    assert_eq!(vector["nullifierTreeHeight"], NULLIFIER_TREE_HEIGHT as u64);
    assert_eq!(vector["transactTag"], tag::TRANSACT as u64);
    assert_eq!(vector["mergeTransactTag"], tag::MERGE_TRANSACT as u64);
    assert_eq!(vector["viewTagLength"], VIEW_TAG_LEN as u64);
    assert_eq!(vector["inputTrees"], INPUT_TREES as u64);
    assert_eq!(vector["maxInputTrees"], MAX_INPUT_TREES as u64);
    assert_eq!(vector["maxSpendInputs"], MAX_SPEND_INPUTS as u64);
}
