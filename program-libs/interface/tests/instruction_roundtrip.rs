use borsh::BorshDeserialize;
use zolana_interface::instruction::{
    encode_instruction, tag, AppendStateLeavesData, CreateAddressTreeData, CreateStateTreeData,
    InstructionTag,
};

#[test]
fn instruction_roundtrip_preserves_tag_and_payload() {
    let payload = CreateAddressTreeData {
        height: 26,
        queue_capacity: 1024,
        canopy_depth: 10,
    };

    let bytes = encode_instruction(tag::CREATE_ADDRESS_TREE, &payload);
    let decoded = CreateAddressTreeData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::CREATE_ADDRESS_TREE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::CreateAddressTree)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn create_state_tree_roundtrip() {
    let payload = CreateStateTreeData {
        height: 26,
        canopy_depth: 10,
    };

    let bytes = encode_instruction(tag::CREATE_STATE_TREE, &payload);
    let decoded = CreateStateTreeData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::CREATE_STATE_TREE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::CreateStateTree)
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
