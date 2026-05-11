use borsh::BorshSerialize;
use shielded_pool_program::process_instruction;
use zolana_interface::instruction::{
    CreateAddressTreeData, InsertAddressesData, ShieldedPoolInstruction,
};

#[test]
fn validates_create_address_tree_instruction() {
    let instruction = ShieldedPoolInstruction::CreateAddressTree(CreateAddressTreeData {
        height: 26,
        queue_capacity: 1024,
        canopy_depth: 10,
    });
    let data = instruction.try_to_vec().unwrap();
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_ok());
}

#[test]
fn rejects_empty_insert_batch() {
    let instruction =
        ShieldedPoolInstruction::InsertAddresses(InsertAddressesData { addresses: vec![] });
    let data = instruction.try_to_vec().unwrap();
    let program_id = pinocchio::Address::from([0u8; 32]);

    assert!(process_instruction(&program_id, &[], &data).is_err());
}
