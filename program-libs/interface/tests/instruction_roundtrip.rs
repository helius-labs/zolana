use borsh::BorshDeserialize;
use zolana_interface::instruction::{
    encode_instruction, tag, BatchUpdateNullifierTreeData, CreateProtocolConfigData,
    CreateZoneConfigData, InputUtxoSignerIndex, InstructionTag, PauseTreeData, TransactIxData,
    UpdateProtocolConfigData, UpdateZoneConfigData, UpdateZoneConfigOwnerData,
    PUBLIC_AMOUNT_DEPOSIT_SPL,
};

#[cfg(feature = "solana")]
use solana_pubkey::Pubkey;
#[cfg(feature = "solana")]
use zolana_interface::instruction::{
    create_spl_interface, create_zone_config, CreateSplInterfaceAccounts,
};

#[test]
fn create_tree_is_tag_only() {
    // create_tree carries no data beyond the tag byte.
    assert_eq!(
        InstructionTag::try_from(tag::CREATE_TREE),
        Ok(InstructionTag::CreateTree)
    );
}

#[test]
fn batch_update_nullifier_tree_roundtrip() {
    let payload = BatchUpdateNullifierTreeData {
        new_root: [3u8; 32],
        compressed_proof_a: [4u8; 32],
        compressed_proof_b: [5u8; 64],
        compressed_proof_c: [6u8; 32],
    };
    let bytes = encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &payload);
    let decoded = BatchUpdateNullifierTreeData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::BATCH_UPDATE_NULLIFIER_TREE);
    assert_eq!(
        InstructionTag::try_from(bytes[0]),
        Ok(InstructionTag::BatchUpdateNullifierTree)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn transact_roundtrip() {
    let payload = TransactIxData {
        expiry_unix_ts: 123,
        sender_view_tag: [1u8; 32],
        proof: [2u8; 192],
        relayer_fee: 3,
        public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SPL,
        nullifiers: vec![[4u8; 32]],
        output_utxo_hashes: vec![[5u8; 32], [6u8; 32]],
        utxo_tree_root_index: vec![7],
        nullifier_tree_root_index: vec![8],
        private_tx_hash: [9u8; 32],
        public_amount: Some(10),
        cpi_signer: None,
        in_utxo_signer_indices: Some(vec![InputUtxoSignerIndex {
            account_index: 1,
            input_index: 0,
        }]),
        encrypted_utxos: vec![12, 13],
        requires_p256: true,
    };
    let bytes = encode_instruction(tag::TRANSACT, &payload);
    let decoded = TransactIxData::try_from_slice(&bytes[1..]).unwrap();

    assert_eq!(bytes[0], tag::TRANSACT);
    assert_eq!(InstructionTag::try_from(bytes[0]), Err(()));
    assert_eq!(decoded, payload);
}

#[test]
fn create_spl_interface_is_tag_only() {
    // create_spl_interface carries no data beyond the tag byte.
    assert_eq!(
        InstructionTag::try_from(tag::CREATE_SPL_INTERFACE),
        Ok(InstructionTag::CreateSplInterface)
    );
}

#[test]
fn protocol_config_roundtrips() {
    let create = CreateProtocolConfigData {
        authority: [1u8; 32],
        merge_authorities: vec![[3u8; 32]],
    };
    let bytes = encode_instruction(tag::CREATE_PROTOCOL_CONFIG, &create);
    assert_eq!(bytes[0], tag::CREATE_PROTOCOL_CONFIG);
    assert_eq!(
        CreateProtocolConfigData::try_from_slice(&bytes[1..]).unwrap(),
        create
    );

    let update = UpdateProtocolConfigData {
        authority: [2u8; 32],
        merge_authorities: vec![[4u8; 32], [5u8; 32]],
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
fn zone_config_update_roundtrips() {
    let create = CreateZoneConfigData {
        program_id: [9u8; 32],
        zone_auth_bump: 255,
        authority: [4u8; 32],
        zone_authority_transact_is_enabled: true,
        zone_config_bump: 254,
    };
    let bytes = encode_instruction(tag::CREATE_ZONE_CONFIG, &create);
    assert_eq!(bytes[0], tag::CREATE_ZONE_CONFIG);
    assert_eq!(
        CreateZoneConfigData::try_from_slice(&bytes[1..]).unwrap(),
        create
    );

    let owner = UpdateZoneConfigOwnerData {
        new_authority: [3u8; 32],
    };
    let bytes = encode_instruction(tag::UPDATE_ZONE_CONFIG_OWNER, &owner);
    assert_eq!(bytes[0], tag::UPDATE_ZONE_CONFIG_OWNER);
    assert_eq!(
        UpdateZoneConfigOwnerData::try_from_slice(&bytes[1..]).unwrap(),
        owner
    );

    let update = UpdateZoneConfigData {
        zone_authority_transact_is_enabled: true,
    };
    let bytes = encode_instruction(tag::UPDATE_ZONE_CONFIG, &update);
    assert_eq!(bytes[0], tag::UPDATE_ZONE_CONFIG);
    assert_eq!(
        UpdateZoneConfigData::try_from_slice(&bytes[1..]).unwrap(),
        update
    );
}

#[test]
#[cfg(feature = "solana")]
fn create_spl_interface_builder_account_layout() {
    let accounts = CreateSplInterfaceAccounts {
        authority: Pubkey::new_unique(),
        protocol_config: Pubkey::new_unique(),
        asset_counter: Pubkey::new_unique(),
        registry: Pubkey::new_unique(),
        mint: Pubkey::new_unique(),
        vault: Pubkey::new_unique(),
        cpi_authority: Pubkey::new_unique(),
        system_program: Pubkey::default(),
        token_program: Pubkey::new_unique(),
    };

    let ix = create_spl_interface(accounts);

    assert_eq!(ix.accounts.len(), 9);
    assert!(ix.accounts[0].is_signer);
    assert!(ix.accounts[0].is_writable);
    assert!(ix.accounts[2].is_writable);
    assert!(ix.accounts[3].is_writable);
    assert!(!ix.accounts[4].is_writable);
    assert!(ix.accounts[5].is_writable);
    assert!(!ix.accounts[6].is_writable);
    assert!(!ix.accounts[7].is_writable);
    assert!(!ix.accounts[8].is_writable);
}

#[test]
#[cfg(feature = "solana")]
fn create_zone_config_builder_account_layout() {
    let payer = Pubkey::new_unique();
    let config = Pubkey::new_unique();
    let zone_auth = Pubkey::new_unique();
    let ix = create_zone_config(
        payer,
        config,
        zone_auth,
        CreateZoneConfigData {
            program_id: Pubkey::new_unique().to_bytes(),
            zone_auth_bump: 255,
            authority: Pubkey::new_unique().to_bytes(),
            zone_authority_transact_is_enabled: true,
            zone_config_bump: 254,
        },
    );

    assert_eq!(ix.accounts.len(), 4);
    assert_eq!(ix.accounts[0].pubkey, payer);
    assert!(ix.accounts[0].is_signer);
    assert!(ix.accounts[0].is_writable);
    assert_eq!(ix.accounts[1].pubkey, config);
    assert!(ix.accounts[1].is_writable);
    assert_eq!(ix.accounts[2].pubkey, zone_auth);
    assert!(ix.accounts[2].is_signer);
    assert!(!ix.accounts[2].is_writable);
    assert_eq!(ix.accounts[3].pubkey, Pubkey::default());
}

#[test]
fn implemented_tags_map_to_instruction_tag() {
    let tags = [
        (
            tag::BATCH_UPDATE_NULLIFIER_TREE,
            InstructionTag::BatchUpdateNullifierTree,
        ),
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
        (tag::CREATE_ZONE_CONFIG, InstructionTag::CreateZoneConfig),
        (
            tag::UPDATE_ZONE_CONFIG_OWNER,
            InstructionTag::UpdateZoneConfigOwner,
        ),
        (tag::UPDATE_ZONE_CONFIG, InstructionTag::UpdateZoneConfig),
    ];

    for (tag, expected) in tags {
        assert_eq!(InstructionTag::try_from(tag), Ok(expected));
    }
}

#[test]
fn unimplemented_tags_are_not_dispatchable() {
    // Tags with no handler must not decode to an InstructionTag; the program
    // dispatch treats them like any unknown byte.
    for tag in [
        tag::TRANSACT,
        tag::reserved::ZONE_TRANSACT,
        tag::reserved::ZONE_AUTHORITY_TRANSACT,
        tag::reserved::MERGE_TRANSACT,
        tag::reserved::ZONE_MERGE_TRANSACT,
    ] {
        assert_eq!(InstructionTag::try_from(tag), Err(()));
    }
}
