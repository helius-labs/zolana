use borsh::BorshDeserialize;
use zolana_interface::instruction::{
    encode_instruction, tag, AppendStateLeavesData, BatchUpdateAddressTreeData, CreatePoolTreeData,
    CreateSplInterfaceData, InsertAddressesData, InstructionTag, TransactData,
    PUBLIC_AMOUNT_DEPOSIT,
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

#[test]
fn transact_roundtrip() {
    let payload = TransactData {
        expiry_unix_ts: 123,
        sender_view_tag: [1u8; 32],
        proof: [2u8; 192],
        relayer_fee: 3,
        public_amount_mode: PUBLIC_AMOUNT_DEPOSIT,
        nullifiers: vec![[4u8; 32]],
        output_utxo_hashes: vec![[5u8; 32], [6u8; 32]],
        utxo_tree_root_index: vec![7],
        nullifier_tree_root_index: vec![8],
        private_tx_hash: [9u8; 32],
        public_sol_amount: None,
        public_spl_amount: Some(10),
        public_spl_asset_id: 11,
        encrypted_utxos: vec![12, 13],
    };
    let bytes = encode_instruction(tag::TRANSACT, &payload);
    let decoded = TransactData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::TRANSACT);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::Transact)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn create_spl_interface_roundtrip() {
    let payload = CreateSplInterfaceData { asset_id: 77 };
    let bytes = encode_instruction(tag::CREATE_SPL_INTERFACE, &payload);
    let decoded = CreateSplInterfaceData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::CREATE_SPL_INTERFACE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::CreateSplInterface)
    );
    assert_eq!(decoded, payload);
}
