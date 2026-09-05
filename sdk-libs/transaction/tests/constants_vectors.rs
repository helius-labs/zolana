use serde_json::Value;
use zolana_interface::instruction::tag;
use zolana_interface::state::tree::{NULLIFIER_TREE_HEIGHT, STATE_HEIGHT};
use zolana_keypair::constants::VIEW_TAG_LEN;
use zolana_transaction::instructions::merge::{MERGE_DEFAULT_INPUTS, MERGE_SUPPORTED_INPUT_COUNTS};

#[test]
fn constants_match_the_shared_vector() {
    let vector: Value =
        serde_json::from_str(include_str!("../../../test-vectors/constants.json")).unwrap();
    assert_eq!(vector["mergeInputs"], MERGE_DEFAULT_INPUTS as u64);
    assert_eq!(
        vector["mergeSupportedInputs"],
        Value::from(
            MERGE_SUPPORTED_INPUT_COUNTS
                .iter()
                .map(|count| *count as u64)
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(vector["stateTreeHeight"], STATE_HEIGHT as u64);
    assert_eq!(vector["nullifierTreeHeight"], NULLIFIER_TREE_HEIGHT as u64);
    assert_eq!(vector["transactTag"], tag::TRANSACT as u64);
    assert_eq!(vector["mergeTransactTag"], tag::MERGE_TRANSACT as u64);
    assert_eq!(vector["viewTagLength"], VIEW_TAG_LEN as u64);
}
