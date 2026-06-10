use borsh::BorshDeserialize;
use zolana_interface::instruction::{
    encode_instruction, tag, AppendStateLeavesData, BatchUpdateAddressTreeData,
    CreatePocketConfigData, CreatePoolTreeData,
    CreateProtocolConfigData, CreateSplInterfaceData, InputUtxoSignerIndex, InsertAddressesData,
    InstructionTag, PauseTreeData, TransactData, UpdatePocketConfigData,
    UpdatePocketConfigOwnerData, UpdateProtocolConfigData, PUBLIC_AMOUNT_DEPOSIT,
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
        cpi_signer: None,
        in_utxo_signer_indices: Some(vec![InputUtxoSignerIndex {
            account_index: 1,
            input_index: 0,
        }]),
        encrypted_utxos: vec![12, 13],
        requires_p256: true,
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
    let payload = CreateSplInterfaceData;
    let bytes = encode_instruction(tag::CREATE_SPL_INTERFACE, &payload);
    let decoded = CreateSplInterfaceData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::CREATE_SPL_INTERFACE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::CreateSplInterface)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn protocol_config_roundtrips() {
    let create = CreateProtocolConfigData {
        authority: [1u8; 32],
    };
    let bytes = encode_instruction(tag::CREATE_PROTOCOL_CONFIG, &create);
    assert_eq!(bytes[0], tag::CREATE_PROTOCOL_CONFIG);
    assert_eq!(
        CreateProtocolConfigData::try_from_slice(&bytes[1..]).unwrap(),
        create
    );

    let update = UpdateProtocolConfigData {
        new_authority: [2u8; 32],
    };
    let bytes = encode_instruction(tag::UPDATE_PROTOCOL_CONFIG, &update);
    assert_eq!(bytes[0], tag::UPDATE_PROTOCOL_CONFIG);
    assert_eq!(
        UpdateProtocolConfigData::try_from_slice(&bytes[1..]).unwrap(),
        update
    );

    let pause = PauseTreeData { paused: true };
    let bytes = encode_instruction(tag::PAUSE_TREE, &pause);
    assert_eq!(bytes[0], tag::PAUSE_TREE);
    assert_eq!(PauseTreeData::try_from_slice(&bytes[1..]).unwrap(), pause);
}

#[test]
fn pocket_config_update_roundtrips() {
    let create = CreatePocketConfigData {
        policy_program_id: [9u8; 32],
        pocket_auth_bump: 255,
        authority: [4u8; 32],
        pocket_authority_transact_is_enabled: true,
        pocket_config_bump: 254,
    };
    let bytes = encode_instruction(tag::CREATE_POCKET_CONFIG, &create);
    assert_eq!(bytes[0], tag::CREATE_POCKET_CONFIG);
    assert_eq!(
        CreatePocketConfigData::try_from_slice(&bytes[1..]).unwrap(),
        create
    );

    let owner = UpdatePocketConfigOwnerData {
        new_authority: [3u8; 32],
    };
    let bytes = encode_instruction(tag::UPDATE_POCKET_CONFIG_OWNER, &owner);
    assert_eq!(bytes[0], tag::UPDATE_POCKET_CONFIG_OWNER);
    assert_eq!(
        UpdatePocketConfigOwnerData::try_from_slice(&bytes[1..]).unwrap(),
        owner
    );

    let update = UpdatePocketConfigData {
        pocket_authority_transact_is_enabled: true,
    };
    let bytes = encode_instruction(tag::UPDATE_POCKET_CONFIG, &update);
    assert_eq!(bytes[0], tag::UPDATE_POCKET_CONFIG);
    assert_eq!(
        UpdatePocketConfigData::try_from_slice(&bytes[1..]).unwrap(),
        update
    );
}

#[test]
fn implemented_tags_map_to_instruction_tag() {
    let tags = [
        (tag::PROOFLESS_SHIELD, InstructionTag::ProoflessShield),
        (
            tag::CREATE_PROTOCOL_CONFIG,
            InstructionTag::CreateProtocolConfig,
        ),
        (
            tag::UPDATE_PROTOCOL_CONFIG,
            InstructionTag::UpdateProtocolConfig,
        ),
        (tag::PAUSE_TREE, InstructionTag::PauseTree),
        (
            tag::CREATE_POCKET_CONFIG,
            InstructionTag::CreatePocketConfig,
        ),
        (
            tag::UPDATE_POCKET_CONFIG_OWNER,
            InstructionTag::UpdatePocketConfigOwner,
        ),
        (
            tag::UPDATE_POCKET_CONFIG,
            InstructionTag::UpdatePocketConfig,
        ),
    ];

    for (tag, expected) in tags {
        assert_eq!(InstructionTag::try_from(tag), Ok(expected));
    }
}

#[test]
fn reserved_unimplemented_tags_are_not_dispatchable() {
    // Spec-reserved tags with no handler must not decode to an InstructionTag;
    // the program dispatch treats them like any unknown byte.
    for tag in [
        tag::reserved::POCKET_TRANSACT,
        tag::reserved::POCKET_AUTHORITY_TRANSACT,
        tag::reserved::MERGE_TRANSACT,
        tag::reserved::ENABLE_MERGE_AUTHORITY,
        tag::reserved::DISABLE_MERGE_AUTHORITY,
        tag::reserved::CREATE_MERGE_AUTHORITY_TREE,
        tag::reserved::MERGE_POCKET,
    ] {
        assert_eq!(InstructionTag::try_from(tag), Err(()));
    }
}
