use borsh::BorshDeserialize;
use zolana_interface::instruction::{
    encode_instruction, tag, CreateAddressTreeData, InstructionTag,
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
