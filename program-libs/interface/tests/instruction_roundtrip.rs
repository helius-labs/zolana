use borsh::{BorshDeserialize, BorshSerialize};
use zolana_interface::instruction::{CreateAddressTreeData, ShieldedPoolInstruction};

#[test]
fn instruction_roundtrip_preserves_tag_and_payload() {
    let instruction = ShieldedPoolInstruction::CreateAddressTree(CreateAddressTreeData {
        height: 26,
        queue_capacity: 1024,
        canopy_depth: 10,
    });

    let bytes = instruction.try_to_vec().unwrap();
    let decoded = ShieldedPoolInstruction::try_from_slice(&bytes).unwrap();

    assert_eq!(decoded, instruction);
    assert_eq!(decoded.tag(), instruction.tag());
}
