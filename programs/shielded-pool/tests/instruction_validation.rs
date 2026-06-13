use shielded_pool_program::process_instruction;
use zolana_interface::instruction::{encode_instruction, tag, CreateTreeData};

fn program_id() -> pinocchio::Address {
    pinocchio::Address::new_from_array([0u8; 32])
}

#[test]
fn rejects_create_tree_without_accounts() {
    let data = encode_instruction(tag::CREATE_TREE, &CreateTreeData);
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_malformed_payload() {
    let data = vec![tag::PROOFLESS_SHIELD, 1, 2, 3];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_unknown_instruction_tag() {
    let data = vec![255];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn encodes_first_byte_tags() {
    let data = encode_instruction(tag::CREATE_TREE, &CreateTreeData);
    assert_eq!(data[0], tag::CREATE_TREE);
}
