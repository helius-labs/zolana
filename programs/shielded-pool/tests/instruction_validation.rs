use shielded_pool_program::process_instruction;
use zolana_interface::instruction::{
    encode_instruction, tag, CreateAddressTreeData, InsertAddressesData,
};

#[test]
fn rejects_create_address_tree_without_accounts() {
    let data = encode_instruction(
        tag::CREATE_ADDRESS_TREE,
        &CreateAddressTreeData {
            height: 26,
            queue_capacity: 1024,
            canopy_depth: 10,
        },
    );
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}

#[test]
fn rejects_invalid_create_address_tree_config() {
    let data = encode_instruction(
        tag::CREATE_ADDRESS_TREE,
        &CreateAddressTreeData {
            height: 0,
            queue_capacity: 1024,
            canopy_depth: 10,
        },
    );
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}

#[test]
fn rejects_empty_insert_batch() {
    let data = encode_instruction(
        tag::INSERT_ADDRESSES,
        &InsertAddressesData { addresses: vec![] },
    );
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}

#[test]
fn rejects_malformed_payload() {
    let data = vec![tag::CREATE_ADDRESS_TREE, 1, 2, 3];
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}

#[test]
fn encodes_first_byte_tags() {
    let data = encode_instruction(
        tag::CREATE_ADDRESS_TREE,
        &CreateAddressTreeData {
            height: 26,
            queue_capacity: 1024,
            canopy_depth: 10,
        },
    );

    assert_eq!(data[0], tag::CREATE_ADDRESS_TREE);
}

#[test]
fn non_empty_insert_without_accounts_does_not_succeed() {
    let data = encode_instruction(
        tag::INSERT_ADDRESSES,
        &InsertAddressesData {
            addresses: vec![[1u8; 32]],
        },
    );
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}

#[test]
fn rejects_unknown_instruction_tag() {
    let data = vec![255];
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}

#[test]
fn create_address_tree_payload_can_be_decoded() {
    let data = CreateAddressTreeData {
        height: 26,
        queue_capacity: 1024,
        canopy_depth: 10,
    };
    let encoded = encode_instruction(tag::CREATE_ADDRESS_TREE, &data);
    let decoded =
        <CreateAddressTreeData as borsh::BorshDeserialize>::try_from_slice(&encoded[1..]).unwrap();

    assert_eq!(decoded, data);
}
