use shielded_pool_program::process_instruction;
use zolana_interface::instruction::{
    encode_instruction, tag, AppendStateLeavesData, CreatePoolTreeData, InsertAddressesData,
};

fn program_id() -> pinocchio::Address {
    pinocchio::Address::new_from_array([0u8; 32])
}

#[test]
fn rejects_create_pool_tree_without_accounts() {
    let data = encode_instruction(tag::CREATE_POOL_TREE, &CreatePoolTreeData);
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn rejects_empty_insert_batch() {
    let data = encode_instruction(
        tag::INSERT_ADDRESSES,
        &InsertAddressesData { addresses: vec![] },
    );
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn rejects_empty_append_state_leaves_batch() {
    let data = encode_instruction(
        tag::APPEND_STATE_LEAVES,
        &AppendStateLeavesData { leaves: vec![] },
    );
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn rejects_malformed_payload() {
    let data = vec![tag::INSERT_ADDRESSES, 1, 2, 3];
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn rejects_unknown_instruction_tag() {
    let data = vec![255];
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn non_empty_insert_without_accounts_does_not_succeed() {
    let data = encode_instruction(
        tag::INSERT_ADDRESSES,
        &InsertAddressesData {
            addresses: vec![[1u8; 32]],
        },
    );
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn non_empty_append_state_leaves_without_accounts_does_not_succeed() {
    let data = encode_instruction(
        tag::APPEND_STATE_LEAVES,
        &AppendStateLeavesData {
            leaves: vec![[1u8; 32]],
        },
    );
    assert!(process_instruction(&program_id(), &[], &data).is_err());
}

#[test]
fn encodes_first_byte_tags() {
    let data = encode_instruction(tag::CREATE_POOL_TREE, &CreatePoolTreeData);
    assert_eq!(data[0], tag::CREATE_POOL_TREE);
}
