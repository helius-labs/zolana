use borsh::BorshDeserialize;
use zolana_interface::{
    event::{
        decode_event_instruction, decode_event_payload, encode_event_instruction,
        encode_event_payload, indexed_events_from_instruction_groups, kind as event_kind,
        EventDecodeError, InstructionGroup, ParsedInstruction, ProoflessShieldEvent,
        ShieldedPoolEvent,
    },
    instruction::{
        encode_instruction, tag, BatchUpdateNullifierTreeData, CreateProtocolConfigData,
        CreateZoneConfigData, InputUtxoSignerIndex, InstructionTag, PauseTreeData,
        ProoflessShieldIxData, TransactInput, TransactIxData, UpdateProtocolConfigData,
        UpdateZoneConfigData, UpdateZoneConfigOwnerData, PUBLIC_AMOUNT_DEPOSIT_SOL,
        PUBLIC_AMOUNT_DEPOSIT_SPL,
    },
};

use solana_pubkey::Pubkey;
#[cfg(feature = "solana")]
use zolana_interface::instruction::{
    create_spl_interface, create_zone_config, proofless_shield, zone_proofless_shield_cpi,
    CpiSignerData, CreateSplInterfaceAccounts, ProoflessShieldAccounts, ProoflessShieldSplAccounts,
    ZoneProoflessShieldIxData,
};
#[cfg(feature = "solana")]
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

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
    // TransactIxData is wincode-encoded (not borsh); the grouped `inputs` vec is
    // non-empty here to exercise the per-input grouping on the wire.
    let payload = TransactIxData {
        expiry_unix_ts: 123,
        sender_view_tag: [1u8; 32],
        proof: [2u8; 192],
        private_tx_hash: [9u8; 32],
        relayer_fee: 3,
        public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SPL,
        requires_p256: true,
        public_amount: Some(10),
        cpi_signer: None,
        inputs: vec![
            TransactInput {
                nullifier: [4u8; 32],
                utxo_tree_root_index: 7,
                nullifier_tree_root_index: 8,
            },
            TransactInput {
                nullifier: [14u8; 32],
                utxo_tree_root_index: 17,
                nullifier_tree_root_index: 18,
            },
        ],
        output_utxo_hashes: vec![[5u8; 32], [6u8; 32]],
        in_utxo_signer_indices: Some(vec![InputUtxoSignerIndex {
            account_index: 1,
            input_index: 0,
        }]),
        encrypted_utxos: vec![12, 13],
    };
    let bytes = payload.serialize().unwrap();
    let decoded = TransactIxData::deserialize(&bytes).unwrap();

    // TRANSACT has no handler, so its tag must not map to an InstructionTag.
    assert_eq!(InstructionTag::try_from(tag::TRANSACT), Err(()));
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
fn proofless_event_roundtrip() {
    let wrapped = sample_event();
    let instruction = encode_event_instruction(&wrapped);
    let payload = encode_event_payload(&wrapped);

    assert_eq!(instruction[0], tag::EMIT_EVENT);
    assert_eq!(instruction[1], event_kind::PROOFLESS_SHIELD);
    assert_eq!(payload, instruction[1..]);
    assert_eq!(decode_event_instruction(&instruction), Ok(wrapped.clone()));
    assert_eq!(decode_event_payload(&payload), Ok(wrapped));
}

#[test]
fn event_parser_indexes_direct_proofless_self_emit() {
    let spp = Pubkey::new_unique();
    let event = sample_event();
    let group = InstructionGroup {
        outer: parsed_ix(spp, tag::PROOFLESS_SHIELD, Some(1)),
        inner: vec![ParsedInstruction::new(
            spp,
            Vec::new(),
            encode_event_instruction(&event),
            Some(2),
        )],
    };

    let events = indexed_events_from_instruction_groups(spp, std::slice::from_ref(&group));

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decoded, Ok(event));
}

#[test]
fn event_parser_ignores_direct_emit_event() {
    let spp = Pubkey::new_unique();
    let event = sample_event();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(spp, Vec::new(), encode_event_instruction(&event), Some(1)),
        inner: Vec::new(),
    };

    let events = indexed_events_from_instruction_groups(spp, std::slice::from_ref(&group));

    assert!(events.is_empty());
}

#[test]
fn event_parser_rejects_wrapper_sibling_emit_event() {
    let spp = Pubkey::new_unique();
    let zone = Pubkey::new_unique();
    let event = sample_event();
    let group = InstructionGroup {
        outer: parsed_ix(zone, tag::ZONE_PROOFLESS_SHIELD, Some(1)),
        inner: vec![
            parsed_ix(spp, tag::ZONE_PROOFLESS_SHIELD, Some(2)),
            ParsedInstruction::new(spp, Vec::new(), encode_event_instruction(&event), Some(3)),
            ParsedInstruction::new(spp, Vec::new(), encode_event_instruction(&event), Some(2)),
        ],
    };

    let events = indexed_events_from_instruction_groups(spp, std::slice::from_ref(&group));

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decoded, Ok(event));
}

#[test]
fn event_decoder_rejects_bad_envelope() {
    assert_eq!(
        decode_event_instruction(&[]),
        Err(EventDecodeError::MissingInstructionTag)
    );
    assert_eq!(
        decode_event_instruction(&[tag::PROOFLESS_SHIELD]),
        Err(EventDecodeError::InvalidInstructionTag(
            tag::PROOFLESS_SHIELD
        ))
    );
    assert_eq!(
        decode_event_payload(&[]),
        Err(EventDecodeError::MissingEventKind)
    );
    assert_eq!(
        decode_event_payload(&[u8::MAX]),
        Err(EventDecodeError::UnknownEventKind(u8::MAX))
    );
}

fn sample_event() -> ShieldedPoolEvent {
    ShieldedPoolEvent::ProoflessShield(ProoflessShieldEvent {
        view_tag: [1u8; 32],
        utxo_hash: [2u8; 32],
        asset: [3u8; 32],
        amount: 42,
        zone_program_id: Some([4u8; 32]),
        policy_data_hash: Some([5u8; 32]),
        owner_utxo_hash: [6u8; 32],
        salt: [7u8; 16],
        program_data_hash: Some([8u8; 32]),
        program_data: Some(vec![9, 10]),
        zone_data: Some(vec![11, 12]),
    })
}

fn parsed_ix(program_id: Pubkey, ix_tag: u8, stack_height: Option<u32>) -> ParsedInstruction {
    ParsedInstruction::new(program_id, Vec::new(), vec![ix_tag], stack_height)
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
#[cfg(feature = "solana")]
fn proofless_shield_account_layouts() {
    let tree = Pubkey::new_unique();
    let depositor = Pubkey::new_unique();
    let sol_accounts = ProoflessShieldAccounts::sol(tree, depositor).account_metas();

    assert_eq!(sol_accounts.len(), 6);
    assert_eq!(sol_accounts[0].pubkey, tree);
    assert!(sol_accounts[0].is_writable);
    assert_eq!(sol_accounts[1].pubkey, depositor);
    assert!(sol_accounts[1].is_signer);
    assert!(sol_accounts[1].is_writable);

    let data = ProoflessShieldIxData {
        view_tag: [1u8; 32],
        owner_utxo_hash: [2u8; 32],
        salt: [3u8; 16],
        public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SOL,
        public_amount: Some(10),
        program_data_hash: None,
        program_data: None,
        cpi_signer: None,
    };
    let spl_accounts = ProoflessShieldSplAccounts {
        user_token: Pubkey::new_unique(),
        vault: Pubkey::new_unique(),
        registry: Pubkey::new_unique(),
        token_program: Pubkey::new_unique(),
    };
    let ix = proofless_shield(
        ProoflessShieldAccounts::spl(tree, depositor, spl_accounts),
        &data,
    );

    assert_eq!(
        ix.program_id,
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
    );
    assert_eq!(ix.accounts.len(), 8);
    assert_eq!(ix.accounts[0].pubkey, tree);
    assert!(ix.accounts[0].is_writable);
    assert_eq!(ix.accounts[1].pubkey, depositor);
    assert!(ix.accounts[1].is_signer);
    assert!(ix.accounts[1].is_writable);
    assert!(ix.accounts[4].is_writable);
    assert!(!ix.accounts[5].is_writable);
    assert!(!ix.accounts[6].is_writable);
    assert!(!ix.accounts[7].is_writable);
}

#[test]
#[cfg(feature = "solana")]
fn zone_proofless_shield_cpi_builder_account_layout() {
    let zone_auth = Pubkey::new_unique();
    let tree = Pubkey::new_unique();
    let depositor = Pubkey::new_unique();
    let ix = zone_proofless_shield_cpi(
        zone_auth,
        tree,
        depositor,
        &ZoneProoflessShieldIxData {
            view_tag: [1u8; 32],
            owner_utxo_hash: [2u8; 32],
            salt: [3u8; 16],
            public_amount_mode: PUBLIC_AMOUNT_DEPOSIT_SPL,
            public_amount: Some(10),
            cpi_signer: CpiSignerData {
                program_id: Pubkey::new_unique().to_bytes(),
                bump: 255,
            },
            policy_data_hash: None,
            zone_data: None,
            program_data_hash: None,
            program_data: None,
        },
    );

    assert_eq!(
        ix.program_id,
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
    );
    assert_eq!(ix.accounts.len(), 7);
    assert_eq!(ix.accounts[0].pubkey, tree);
    assert!(ix.accounts[0].is_writable);
    assert_eq!(ix.accounts[1].pubkey, depositor);
    assert!(ix.accounts[1].is_signer);
    assert!(ix.accounts[1].is_writable);
    assert_eq!(ix.accounts[2].pubkey, zone_auth);
    assert!(ix.accounts[2].is_signer);
    assert!(!ix.accounts[2].is_writable);
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
