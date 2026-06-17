use shielded_pool_program::process_instruction;
use zolana_interface::instruction::tag;

fn program_id() -> pinocchio::Address {
    pinocchio::Address::new_from_array([0u8; 32])
}

#[test]
fn rejects_create_tree_without_accounts() {
    let data = vec![tag::CREATE_TREE];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_malformed_payload() {
    let data = vec![tag::DEPOSIT, 1, 2, 3];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_unknown_instruction_tag() {
    let data = vec![255];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn encodes_first_byte_tags() {
    let data = [tag::CREATE_TREE];
    assert_eq!(data[0], tag::CREATE_TREE);
}
