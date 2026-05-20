use borsh::BorshDeserialize;
use zolana_interface::instruction::{
    encode_instruction, tag, AppendStateLeavesData, BatchUpdateAddressTreeData, CreatePoolTreeData,
    InsertAddressesData, InstructionTag,
};

#[test]
fn create_pool_tree_roundtrip() {
    let payload = CreatePoolTreeData;
    let bytes = encode_instruction(tag::CREATE_POOL_TREE, &payload);
    let decoded = CreatePoolTreeData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::CREATE_POOL_TREE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::CreatePoolTree)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn insert_addresses_roundtrip() {
    let payload = InsertAddressesData {
        addresses: vec![[7u8; 32], [8u8; 32]],
    };
    let bytes = encode_instruction(tag::INSERT_ADDRESSES, &payload);
    let decoded = InsertAddressesData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::INSERT_ADDRESSES);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::InsertAddresses)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn append_state_leaves_roundtrip() {
    let payload = AppendStateLeavesData {
        leaves: vec![[1u8; 32], [2u8; 32]],
    };
    let bytes = encode_instruction(tag::APPEND_STATE_LEAVES, &payload);
    let decoded = AppendStateLeavesData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::APPEND_STATE_LEAVES);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::AppendStateLeaves)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn batch_update_address_tree_roundtrip() {
    let payload = BatchUpdateAddressTreeData {
        cpi_authority_bump: 254,
        new_root: [3u8; 32],
        compressed_proof_a: [4u8; 32],
        compressed_proof_b: [5u8; 64],
        compressed_proof_c: [6u8; 32],
    };
    let bytes = encode_instruction(tag::BATCH_UPDATE_ADDRESS_TREE, &payload);
    let decoded = BatchUpdateAddressTreeData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::BATCH_UPDATE_ADDRESS_TREE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::BatchUpdateAddressTree)
    );
    assert_eq!(decoded, payload);
}
