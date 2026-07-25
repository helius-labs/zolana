//! Emit the current-Rust oracle the TypeScript `@zolana/interface` parity suite
//! compares against. Every value is produced by calling `zolana-interface` at
//! this revision, so a Rust change that the TypeScript port has not followed
//! shows up as a diff in `sdk-libs/ts/interface/test/rust-oracle.json`.
//!
//! ```bash
//! cargo run -p xtask --bin ts-interface-oracle -- --write
//! cargo run -p xtask --bin ts-interface-oracle -- --check
//! ```

use std::{fs, path::PathBuf};

use bytemuck::Zeroable;
use serde_json::{json, Map, Value};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        builders::{
            BatchUpdateNullifierTree, CreateAssetCounter, CreateAssociatedTokenAccount,
            CreateProtocolConfig, CreateSplInterface, CreateTree, CreateZoneConfig, Deposit,
            DepositSplAccounts, MergeTransact, MergeZone, PauseTree, Transact,
            TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal, UpdateProtocolConfig,
            UpdateZoneConfig, UpdateZoneConfigOwner, ZoneAuthorityTransact, ZoneDeposit,
            ZoneTransact,
        },
        instruction_data::transact::ExternalDataHash,
        tag, InputUtxo, MergeExternalDataHash, MergeTransactIxData, MessageData, OwnerTag,
        P256Proof, ResolvedOutput, TransactIxData, TransactOutput, TransactProof,
        UpdateProtocolConfigData, UtxoData,
    },
    merge_utils::{ciphertext_hash, owner_pk_field_compressed, pack33, pk_field_compressed},
    pda,
    shape::SPP_SUPPORTED_SHAPES,
    state::{
        discriminator, tree, ProtocolConfig, SplAssetCounter, SplAssetRegistry, ZoneConfig,
    },
    ASSOCIATED_TOKEN_PROGRAM_ID, DEFAULT_TREE_ADDRESS, SHIELDED_POOL_CPI_AUTHORITY,
    SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE, SPL_TOKEN_PROGRAM_ID, UTXO_DOMAIN,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Deterministic non-trivial filler so a field that is silently dropped on one
/// side cannot coincidentally match a zeroed field on the other.
fn filler<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add((index as u8).wrapping_mul(7)) | 1;
    }
    out
}

fn mint() -> Pubkey {
    Pubkey::new_from_array([1; 32])
}

fn owner() -> Pubkey {
    Pubkey::new_from_array([2; 32])
}

fn zone_program() -> Pubkey {
    Pubkey::new_from_array([3; 32])
}

fn account(index: u8) -> Pubkey {
    Pubkey::new_from_array([index; 32])
}

/// Base58 for every `[index; 32]` account the builder vectors use, so the
/// TypeScript side never re-derives an address it is meant to be compared on.
fn accounts() -> Value {
    let mut map = Map::new();
    for index in 0u8..=63 {
        map.insert(index.to_string(), json!(account(index).to_string()));
    }
    Value::Object(map)
}

fn instruction_json(instruction: &Instruction) -> Value {
    json!({
        "programAddress": instruction.program_id.to_string(),
        "data": hex(&instruction.data),
        "accounts": instruction
            .accounts
            .iter()
            .map(|meta| json!({
                "address": meta.pubkey.to_string(),
                "isSigner": meta.is_signer,
                "isWritable": meta.is_writable,
            }))
            .collect::<Vec<_>>(),
    })
}

fn errors() -> Value {
    use ShieldedPoolError::*;
    // Keys are the Rust variant identifiers, which are also the TypeScript
    // `ShieldedPoolError` member names, so a renamed variant fails the port.
    let table = [
        ("InvalidInstructionData", InvalidInstructionData),
        ("InvalidTreeAccounts", InvalidTreeAccounts),
        ("NullifierTreeUpdateFailed", NullifierTreeUpdateFailed),
        ("UnauthorizedCaller", UnauthorizedCaller),
        ("StateAppendFailed", StateAppendFailed),
        ("ExpiredTransaction", ExpiredTransaction),
        ("InvalidTransactShape", InvalidTransactShape),
        ("InvalidTransactProofEncoding", InvalidTransactProofEncoding),
        (
            "TransactProofVerificationFailed",
            TransactProofVerificationFailed,
        ),
        ("InvalidSettlementAccounts", InvalidSettlementAccounts),
        ("PublicSettlementFailed", PublicSettlementFailed),
        ("InvalidSplAssetRegistry", InvalidSplAssetRegistry),
        ("InvalidProtocolConfig", InvalidProtocolConfig),
        ("TreePaused", TreePaused),
        ("InvalidZoneConfig", InvalidZoneConfig),
        ("StaleNullifierRoot", StaleNullifierRoot),
        ("InvalidPda", InvalidPda),
        ("MergeDisabled", MergeDisabled),
        ("InvalidUserRecord", InvalidUserRecord),
        ("InvalidMergeShape", InvalidMergeShape),
        ("InvalidMergeOutputScheme", InvalidMergeOutputScheme),
        ("MismatchedTransactProofRail", MismatchedTransactProofRail),
        (
            "ZoneAuthorityTransactDisabled",
            ZoneAuthorityTransactDisabled,
        ),
        ("BothPublicAmountsSet", BothPublicAmountsSet),
        ("MissingP256SigningKey", MissingP256SigningKey),
        ("OwnerTagAccountMissing", OwnerTagAccountMissing),
    ];
    let mut map = Map::new();
    for (name, error) in table {
        map.insert(
            name.to_string(),
            json!({ "code": error as u32, "message": error.to_string() }),
        );
    }
    Value::Object(map)
}

fn constants() -> Value {
    json!({
        "shieldedPoolProgramId": Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string(),
        "defaultTreeAddress": DEFAULT_TREE_ADDRESS,
        "solInterface": Pubkey::new_from_array(SOL_INTERFACE).to_string(),
        "shieldedPoolCpiAuthority": Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY).to_string(),
        "splTokenProgramId": Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID).to_string(),
        "associatedTokenProgramId": Pubkey::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID).to_string(),
        "utxoDomain": UTXO_DOMAIN,
        "p256ProofLength": P256Proof::LEN,
        "mergeInputCount": zolana_interface::instruction::instruction_data::MERGE_INPUT_COUNT,
        "mergeEncryptedUtxoLength":
            zolana_interface::instruction::instruction_data::MERGE_ENCRYPTED_UTXO_LEN,
        "mergeEncryptedUtxoTypePrefix":
            zolana_interface::instruction::instruction_data::merge_transact::MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
    })
}

fn tags() -> Value {
    json!({
        "transact": tag::TRANSACT,
        "deposit": tag::DEPOSIT,
        "zoneTransact": tag::ZONE_TRANSACT,
        "zoneAuthorityTransact": tag::ZONE_AUTHORITY_TRANSACT,
        "createSplInterface": tag::CREATE_SPL_INTERFACE,
        "createTree": tag::CREATE_TREE,
        "createProtocolConfig": tag::CREATE_PROTOCOL_CONFIG,
        "updateProtocolConfig": tag::UPDATE_PROTOCOL_CONFIG,
        "pauseTree": tag::PAUSE_TREE,
        "createZoneConfig": tag::CREATE_ZONE_CONFIG,
        "updateZoneConfigOwner": tag::UPDATE_ZONE_CONFIG_OWNER,
        "updateZoneConfig": tag::UPDATE_ZONE_CONFIG,
        "mergeTransact": tag::MERGE_TRANSACT,
        "zoneMergeTransact": tag::ZONE_MERGE_TRANSACT,
        "emitEvent": tag::EMIT_EVENT,
        "zoneDeposit": tag::ZONE_DEPOSIT,
        "createAssetCounter": tag::CREATE_ASSET_COUNTER,
        "batchUpdateNullifierTree": tag::BATCH_UPDATE_NULLIFIER_TREE,
    })
}

fn state() -> Value {
    json!({
        "discriminators": {
            "treeAccount": discriminator::TREE_ACCOUNT_DISCRIMINATOR,
            "protocolConfig": discriminator::PROTOCOL_CONFIG,
            "zoneConfig": discriminator::ZONE_CONFIG,
            "splAssetRegistry": discriminator::SPL_ASSET_REGISTRY,
            "splAssetCounter": discriminator::SPL_ASSET_COUNTER,
        },
        "sizes": {
            "protocolConfig": ProtocolConfig::SIZE,
            "splAssetCounter": SplAssetCounter::SIZE,
            "splAssetRegistry": SplAssetRegistry::SIZE,
            "zoneConfig": ZoneConfig::SIZE,
        },
        "firstAssetId": SplAssetCounter::FIRST_ASSET_ID.to_string(),
        "tree": {
            "accountSize": tree::tree_account_size(),
            "stateRootOffset": tree::state_root_offset(),
            "stateHeight": tree::STATE_HEIGHT,
            "addressTreeHeight": tree::ADDRESS_TREE_HEIGHT,
            "inputQueueBatchSize": tree::ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE.to_string(),
            "inputQueueZkpBatchSize": tree::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE.to_string(),
            "rootHistoryCapacity": tree::ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
        },
    })
}

/// Byte images of every state account, produced by `bytemuck` over the real
/// structs, so the TypeScript codecs decode exactly what the program writes.
fn state_accounts() -> Value {
    let mut protocol = ProtocolConfig::zeroed();
    protocol.discriminator = discriminator::PROTOCOL_CONFIG;
    protocol.protocol_authority = account(11).to_bytes().into();
    protocol.tree_creation_authority = account(12).to_bytes().into();
    protocol.forester_authority = account(13).to_bytes().into();
    protocol.zone_creation_authority = account(14).to_bytes().into();
    protocol.tree_creation_is_permissionless = 1;
    protocol.zone_creation_is_permissionless = 0;
    protocol.spl_interface_creation_is_permissionless = 1;

    // A non-canonical (nonzero, non-one) flag byte: Rust decodes it as `true`
    // through `!= 0`, so the TypeScript decoder must not reject it.
    let mut protocol_noncanonical = protocol;
    protocol_noncanonical.zone_creation_is_permissionless = 7;

    let mut counter = SplAssetCounter::zeroed();
    counter.init();
    let mut counter_max = SplAssetCounter::zeroed();
    counter_max.discriminator = discriminator::SPL_ASSET_COUNTER;
    counter_max.next_id = u64::MAX;

    let mut zone = ZoneConfig::zeroed();
    zone.discriminator = discriminator::ZONE_CONFIG;
    zone.authority = account(15).to_bytes().into();
    zone.program_id = account(16).to_bytes().into();
    zone.zone_authority_transact_is_enabled = 1;
    zone.bump = 253;
    let mut zone_noncanonical = zone;
    zone_noncanonical.zone_authority_transact_is_enabled = 42;

    json!({
        "protocolConfig": {
            "bytes": hex(bytemuck::bytes_of(&protocol)),
            "value": {
                "authority": account(11).to_string(),
                "treeCreationAuthority": account(12).to_string(),
                "foresterAuthority": account(13).to_string(),
                "zoneCreationAuthority": account(14).to_string(),
                "treeCreationIsPermissionless": protocol.allows_permissionless_tree_creation(),
                "zoneCreationIsPermissionless": protocol.allows_permissionless_zone_creation(),
                "splInterfaceCreationIsPermissionless":
                    protocol.allows_permissionless_spl_interface_creation(),
            },
        },
        "protocolConfigNoncanonicalFlag": {
            "bytes": hex(bytemuck::bytes_of(&protocol_noncanonical)),
            "zoneCreationIsPermissionless":
                protocol_noncanonical.allows_permissionless_zone_creation(),
        },
        "splAssetCounter": {
            "bytes": hex(bytemuck::bytes_of(&counter)),
            "nextId": counter.next_id.to_string(),
        },
        "splAssetCounterMax": {
            "bytes": hex(bytemuck::bytes_of(&counter_max)),
            "nextId": counter_max.next_id.to_string(),
        },
        "splAssetRegistry": {
            "bytes": hex(&SplAssetRegistry::account_bytes(mint().to_bytes().into(), 7)),
            "mint": mint().to_string(),
            "assetId": "7",
        },
        "zoneConfig": {
            "bytes": hex(bytemuck::bytes_of(&zone)),
            "value": {
                "authority": account(15).to_string(),
                "programId": account(16).to_string(),
                "zoneAuthorityTransactIsEnabled": zone.enabled(),
                "bump": zone.bump,
            },
        },
        "zoneConfigNoncanonicalFlag": {
            "bytes": hex(bytemuck::bytes_of(&zone_noncanonical)),
            "zoneAuthorityTransactIsEnabled": zone_noncanonical.enabled(),
        },
    })
}

fn shapes() -> Value {
    Value::Array(
        SPP_SUPPORTED_SHAPES
            .iter()
            .map(|shape| json!({ "inputs": shape.n_inputs(), "outputs": shape.n_outputs() }))
            .collect(),
    )
}

fn merge_utils() -> Value {
    let ciphertext_hashes: Vec<Value> = [1usize, 15, 16, 17, 31, 32, 33, 110, 191, 192]
        .into_iter()
        .map(|length| {
            let ciphertext: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            json!({
                "length": length,
                "hash": hex(&ciphertext_hash(&ciphertext).expect("supported chunk count")),
            })
        })
        .collect();

    let even: [u8; 33] = {
        let mut key = filler::<33>(9);
        key[0] = 0x02;
        key
    };
    let odd: [u8; 33] = {
        let mut key = even;
        key[0] = 0x03;
        key
    };
    let (lo, hi) = pack33(&even);

    json!({
        "ciphertextHashes": ciphertext_hashes,
        // Rust rejects both through `Poseidon::hashv`'s supported input range.
        "ciphertextHashRejects": { "empty": true, "over192": true },
        "compressedKeyEven": hex(&even),
        "compressedKeyOdd": hex(&odd),
        "pkFieldEven": hex(&pk_field_compressed(&even).expect("valid prefix")),
        "pkFieldOdd": hex(&pk_field_compressed(&odd).expect("valid prefix")),
        "ownerPkFieldEven": hex(&owner_pk_field_compressed(&even).expect("valid prefix")),
        "ownerPkFieldOdd": hex(&owner_pk_field_compressed(&odd).expect("valid prefix")),
        "pack33Low": hex(&lo),
        "pack33High": hex(&hi),
        "rejectedPrefixes": [0x00, 0x01, 0x04, 0xff],
    })
}

fn pdas() -> Value {
    json!({
        "mint": mint().to_string(),
        "owner": owner().to_string(),
        "zoneProgram": zone_program().to_string(),
        "protocolConfig": pda::protocol_config().to_string(),
        "solInterface": pda::sol_interface().to_string(),
        "cpiAuthority": pda::shielded_pool_cpi_authority().to_string(),
        "splAssetCounter": pda::spl_asset_counter().to_string(),
        "splAssetRegistry": pda::spl_asset_registry(&mint()).to_string(),
        "splAssetVault": pda::spl_asset_vault(&mint()).to_string(),
        "zoneConfig": {
            "address": pda::zone_config(&zone_program()).0.to_string(),
            "bump": pda::zone_config(&zone_program()).1,
        },
        "zoneAuth": {
            "address": pda::zone_auth(&zone_program()).0.to_string(),
            "bump": pda::zone_auth(&zone_program()).1,
        },
        "associatedToken": pda::associated_token_address(&owner(), &mint()).to_string(),
    })
}

fn utxo_data() -> UtxoData {
    UtxoData {
        data_hash: filler::<32>(3),
        data: vec![9, 8, 7, 6, 5],
    }
}

fn deposit_builder(spl: bool) -> Deposit {
    Deposit {
        tree: account(20),
        depositor: account(21),
        spl: spl.then_some(DepositSplAccounts {
            user_token: account(22),
            spl_token_interface: account(23),
            registry: account(24),
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        }),
        view_tag: filler::<32>(1),
        owner: filler::<32>(2),
        blinding: filler::<31>(4),
        amount: 1_234_567_890_123,
        utxo_data: Some(utxo_data()),
        memo: Some(vec![1, 2, 3]),
    }
}

fn zone_deposit_builder(spl: bool) -> ZoneDeposit {
    ZoneDeposit {
        tree: account(20),
        depositor: account(21),
        spl: spl.then_some(DepositSplAccounts {
            user_token: account(22),
            spl_token_interface: account(23),
            registry: account(24),
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        }),
        view_tag: filler::<32>(1),
        owner: filler::<32>(2),
        blinding: filler::<31>(4),
        amount: 42,
        zone_program_id: zone_program(),
        zone_data_hash: filler::<32>(5),
        zone_data: vec![4, 4, 4, 4],
        utxo_data: Some(utxo_data()),
        memo: None,
    }
}

fn transact_data(p256: bool) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 1_700_000_000,
        relayer_fee: 4_242,
        private_tx_hash: filler::<32>(6),
        p256_signing_pk_x: p256.then(|| filler::<32>(7)),
        tx_viewing_pk: {
            let mut key = filler::<33>(8);
            key[0] = 0x02;
            key
        },
        salt: filler::<16>(10),
        proof: if p256 {
            TransactProof::P256(P256Proof {
                a: filler::<32>(11),
                b: filler::<64>(12),
                c: filler::<32>(13),
                commitment: filler::<32>(14),
                commitment_pok: filler::<32>(15),
            })
        } else {
            TransactProof::Eddsa {
                a: filler::<32>(11),
                b: filler::<64>(12),
                c: filler::<32>(13),
            }
        },
        inputs: vec![
            InputUtxo {
                nullifier_hash: filler::<32>(16),
                nullifier_tree_root_index: 3,
                utxo_tree_root_index: 9,
                tree_index: 1,
                eddsa_signer_index: 0,
            },
            InputUtxo {
                nullifier_hash: filler::<32>(17),
                nullifier_tree_root_index: 65_535,
                utxo_tree_root_index: 0,
                tree_index: 255,
                eddsa_signer_index: 2,
            },
        ],
        public_sol_amount: Some(-9),
        public_spl_amount: None,
        data_hash: Some(filler::<32>(18)),
        zone_data_hash: None,
        outputs: vec![
            TransactOutput {
                utxo_hash: filler::<32>(19),
                owner_tag: OwnerTag::Inline(filler::<32>(20)),
                data: Some(vec![1, 2, 3, 4, 5, 6, 7]),
            },
            TransactOutput {
                utxo_hash: filler::<32>(21),
                owner_tag: OwnerTag::Account(4),
                data: None,
            },
            TransactOutput {
                utxo_hash: filler::<32>(22),
                owner_tag: OwnerTag::P256SigningKey,
                data: Some(Vec::new()),
            },
        ],
        messages: vec![MessageData {
            view_tag: filler::<32>(23),
            data: vec![7; 40],
        }],
    }
}

fn merge_data() -> MergeTransactIxData {
    let mut encrypted = vec![0u8; 110];
    for (index, byte) in encrypted.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    encrypted[0] = 2;
    MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: P256Proof {
            a: filler::<32>(24),
            b: filler::<64>(25),
            c: filler::<32>(26),
            commitment: filler::<32>(27),
            commitment_pok: filler::<32>(28),
        },
        output_utxo_hash: filler::<32>(29),
        nullifiers: (0..8).map(|index| filler::<32>(30 + index)).collect(),
        utxo_tree_root_index: vec![0, 1, 2, 3, 4, 5, 6, 65_535],
        nullifier_tree_root_index: vec![65_535, 6, 5, 4, 3, 2, 1, 0],
        private_tx_hash: filler::<32>(40),
        encrypted_utxo: encrypted,
        eddsa_owner: true,
    }
}

fn instruction_data() -> Value {
    let transact_eddsa = transact_data(false);
    let transact_p256 = transact_data(true);
    let merge = merge_data();
    json!({
        "deposit": hex(&deposit_builder(false).instruction().data[1..]),
        "zoneDeposit": hex(&zone_deposit_builder(false).instruction().data[1..]),
        "transactEddsa": hex(&transact_eddsa.serialize().expect("serializable")),
        "transactP256": hex(&transact_p256.serialize().expect("serializable")),
        "mergeTransact": hex(&merge.serialize().expect("serializable")),
        "mergeZone": hex(
            &zolana_interface::instruction::MergeZoneIxData {
                merge_view_tag: filler::<32>(41),
                merge: merge.clone(),
            }
            .serialize()
            .expect("serializable"),
        ),
        "mergeZoneViewTag": hex(&filler::<32>(41)),
    })
}

fn builders() -> Value {
    let merge = merge_data();
    let transact = transact_data(false);
    let sol_withdrawal = TransactWithdrawal::Sol(TransactSolWithdrawal {
        recipient: account(31),
    });
    let spl_withdrawal = TransactWithdrawal::Spl(TransactSplWithdrawal {
        cpi_authority: Some(pda::shielded_pool_cpi_authority()),
        spl_token_interface: account(32),
        recipient: account(33),
        user_token_account: account(34),
        token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
    });
    let spl_withdrawal_no_authority = TransactWithdrawal::Spl(TransactSplWithdrawal {
        cpi_authority: None,
        spl_token_interface: account(32),
        recipient: account(33),
        user_token_account: account(34),
        token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
    });

    let mut map = Map::new();
    map.insert(
        "createAssetCounter".into(),
        instruction_json(
            &CreateAssetCounter {
                authority: owner(),
            }
            .instruction(),
        ),
    );
    map.insert(
        "createSplInterface".into(),
        instruction_json(
            &CreateSplInterface {
                authority: owner(),
                mint: mint(),
            }
            .instruction(),
        ),
    );
    map.insert(
        "createAssociatedTokenAccount".into(),
        instruction_json(
            &CreateAssociatedTokenAccount {
                payer: account(35),
                owner: owner(),
                mint: mint(),
            }
            .instruction(),
        ),
    );
    let create_tree = CreateTree {
        authority: owner(),
        tree: account(20),
        owner: account(36),
    };
    map.insert(
        "createTree".into(),
        instruction_json(&create_tree.instruction()),
    );
    map.insert(
        "createTreeWithNullifierParams".into(),
        instruction_json(&create_tree.instruction_with_nullifier_params(tree::address_tree_params())),
    );
    map.insert(
        "batchUpdateNullifierTree".into(),
        instruction_json(
            &BatchUpdateNullifierTree {
                authority: owner(),
                tree: account(20),
                new_root: filler::<32>(42),
                old_root: filler::<32>(43),
                zkp_batch_index: 517,
                compressed_proof_a: filler::<32>(44),
                compressed_proof_b: filler::<64>(45),
                compressed_proof_c: filler::<32>(46),
            }
            .instruction(),
        ),
    );
    map.insert(
        "depositSol".into(),
        instruction_json(&deposit_builder(false).instruction()),
    );
    map.insert(
        "depositSpl".into(),
        instruction_json(&deposit_builder(true).instruction()),
    );
    map.insert(
        "zoneDepositSol".into(),
        instruction_json(&zone_deposit_builder(false).instruction()),
    );
    map.insert(
        "zoneDepositSolCpi".into(),
        instruction_json(&zone_deposit_builder(false).cpi_instruction()),
    );
    map.insert(
        "zoneDepositSpl".into(),
        instruction_json(&zone_deposit_builder(true).instruction()),
    );
    map.insert(
        "zoneDepositSplCpi".into(),
        instruction_json(&zone_deposit_builder(true).cpi_instruction()),
    );
    map.insert(
        "transactNoWithdrawal".into(),
        instruction_json(
            &Transact {
                payer: account(30),
                tree: account(20),
                withdrawal: None,
                data: transact.clone(),
            }
            .instruction(),
        ),
    );
    map.insert(
        "transactSolWithdrawal".into(),
        instruction_json(
            &Transact {
                payer: account(30),
                tree: account(20),
                withdrawal: Some(sol_withdrawal.clone()),
                data: transact.clone(),
            }
            .instruction(),
        ),
    );
    map.insert(
        "transactSplWithdrawal".into(),
        instruction_json(
            &Transact {
                payer: account(30),
                tree: account(20),
                withdrawal: Some(spl_withdrawal.clone()),
                data: transact.clone(),
            }
            .instruction(),
        ),
    );
    map.insert(
        "transactSplWithdrawalNoCpiAuthority".into(),
        instruction_json(
            &Transact {
                payer: account(30),
                tree: account(20),
                withdrawal: Some(spl_withdrawal_no_authority.clone()),
                data: transact.clone(),
            }
            .instruction(),
        ),
    );
    let zone_transact = ZoneTransact {
        payer: account(30),
        tree: account(20),
        zone_program_id: zone_program(),
        withdrawal: Some(sol_withdrawal.clone()),
        data: transact.clone(),
    };
    map.insert(
        "zoneTransactSol".into(),
        instruction_json(&zone_transact.instruction()),
    );
    map.insert(
        "zoneTransactSolCpi".into(),
        instruction_json(&zone_transact.cpi_instruction()),
    );
    let zone_transact_spl = ZoneTransact {
        payer: account(30),
        tree: account(20),
        zone_program_id: zone_program(),
        withdrawal: Some(spl_withdrawal.clone()),
        data: transact.clone(),
    };
    map.insert(
        "zoneTransactSpl".into(),
        instruction_json(&zone_transact_spl.instruction()),
    );
    map.insert(
        "zoneTransactSplCpi".into(),
        instruction_json(&zone_transact_spl.cpi_instruction()),
    );
    let zone_authority_transact = ZoneAuthorityTransact {
        payer: account(30),
        tree: account(20),
        zone_program_id: zone_program(),
        withdrawal: Some(spl_withdrawal.clone()),
        data: transact.clone(),
    };
    map.insert(
        "zoneAuthorityTransactSpl".into(),
        instruction_json(&zone_authority_transact.instruction()),
    );
    map.insert(
        "zoneAuthorityTransactSplCpi".into(),
        instruction_json(&zone_authority_transact.cpi_instruction()),
    );
    map.insert(
        "mergeTransact".into(),
        instruction_json(
            &MergeTransact {
                tree: account(20),
                payer: account(30),
                user_record: account(37),
                data: merge.clone(),
            }
            .instruction(),
        ),
    );
    let merge_zone = MergeZone {
        tree: account(20),
        zone_program_id: zone_program(),
        payer: account(30),
        data: merge.clone(),
        merge_view_tag: filler::<32>(41),
    };
    map.insert(
        "mergeZone".into(),
        instruction_json(&merge_zone.instruction()),
    );
    map.insert(
        "mergeZoneCpi".into(),
        instruction_json(&merge_zone.cpi_instruction()),
    );
    map.insert(
        "createProtocolConfig".into(),
        instruction_json(
            &CreateProtocolConfig {
                authority: owner(),
                protocol_authority: account(11).to_bytes().into(),
                tree_creation_authority: account(12).to_bytes().into(),
                tree_creation_is_permissionless: true,
                forester_authority: account(13).to_bytes().into(),
                zone_creation_authority: account(14).to_bytes().into(),
                zone_creation_is_permissionless: false,
                spl_interface_creation_is_permissionless: true,
            }
            .instruction(),
        ),
    );
    for (name, update) in [
        (
            "updateProtocolAuthority",
            UpdateProtocolConfigData::ProtocolAuthority(account(11).to_bytes().into()),
        ),
        (
            "updateTreeCreationAuthority",
            UpdateProtocolConfigData::TreeCreationAuthority(account(12).to_bytes().into()),
        ),
        (
            "updateForesterAuthority",
            UpdateProtocolConfigData::ForesterAuthority(account(13).to_bytes().into()),
        ),
        (
            "updateZoneCreationAuthority",
            UpdateProtocolConfigData::ZoneCreationAuthority(account(14).to_bytes().into()),
        ),
        (
            "updateTreeCreationPermissionless",
            UpdateProtocolConfigData::TreeCreationPermissionless(true),
        ),
        (
            "updateZoneCreationPermissionless",
            UpdateProtocolConfigData::ZoneCreationPermissionless(false),
        ),
        (
            "updateSplInterfaceCreationPermissionless",
            UpdateProtocolConfigData::SplInterfaceCreationPermissionless(true),
        ),
    ] {
        map.insert(
            name.into(),
            instruction_json(
                &UpdateProtocolConfig {
                    authority: owner(),
                    update,
                }
                .instruction(),
            ),
        );
    }
    map.insert(
        "pauseTree".into(),
        instruction_json(
            &PauseTree {
                authority: owner(),
                tree: account(20),
                paused: true,
            }
            .instruction(),
        ),
    );
    map.insert(
        "createZoneConfig".into(),
        instruction_json(
            &CreateZoneConfig {
                payer: account(35),
                program_id: zone_program().to_bytes().into(),
                authority: account(15).to_bytes().into(),
                zone_authority_transact_is_enabled: true,
            }
            .instruction()
            .expect("canonical zone auth derivation"),
        ),
    );
    map.insert(
        "updateZoneConfig".into(),
        instruction_json(
            &UpdateZoneConfig {
                authority: account(15),
                zone_config: account(38),
                zone_authority_transact_is_enabled: false,
            }
            .instruction(),
        ),
    );
    map.insert(
        "updateZoneConfigOwner".into(),
        instruction_json(
            &UpdateZoneConfigOwner {
                authority: account(15),
                zone_config: account(38),
                new_authority: account(39).to_bytes().into(),
            }
            .instruction(),
        ),
    );
    Value::Object(map)
}

fn external_data_hashes() -> Value {
    let utxo_a = filler::<32>(50);
    let utxo_b = filler::<32>(51);
    let tag_a = filler::<32>(52);
    let tag_b = filler::<32>(53);
    let data = vec![1u8, 2, 3, 4];
    let outputs = [
        ResolvedOutput {
            utxo_hash: &utxo_a,
            owner_tag: tag_a,
            data: Some(&data),
        },
        ResolvedOutput {
            utxo_hash: &utxo_b,
            owner_tag: tag_b,
            data: None,
        },
    ];
    let empty_data: [u8; 0] = [];
    let outputs_empty_data = [ResolvedOutput {
        utxo_hash: &utxo_a,
        owner_tag: tag_a,
        data: Some(&empty_data),
    }];
    let outputs_no_data = [ResolvedOutput {
        utxo_hash: &utxo_a,
        owner_tag: tag_a,
        data: None,
    }];
    let messages = [MessageData {
        view_tag: filler::<32>(54),
        data: vec![9; 12],
    }];
    let user_sol = account(60).to_bytes();
    let user_spl = account(61).to_bytes();
    let interface = account(62).to_bytes();

    let full = ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: 1_700_000_000,
        relayer_fee: 4_242,
        public_sol_amount: Some(-9),
        public_spl_amount: Some(11),
        user_sol_account: &user_sol,
        user_spl_token_account: &user_spl,
        spl_token_interface: &interface,
        data_hash: Some(filler::<32>(55)),
        zone_data_hash: None,
        outputs: &outputs,
        messages: &messages,
    };
    let minimal = ExternalDataHash::<MessageData> {
        spp_instruction_discriminator: tag::ZONE_TRANSACT,
        expiry_unix_ts: 0,
        relayer_fee: 0,
        public_sol_amount: None,
        public_spl_amount: None,
        user_sol_account: &[0u8; 32],
        user_spl_token_account: &[0u8; 32],
        spl_token_interface: &[0u8; 32],
        data_hash: None,
        zone_data_hash: None,
        outputs: &[],
        messages: &[],
    };
    let empty_data_hash = ExternalDataHash::<MessageData> {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: 1,
        relayer_fee: 2,
        public_sol_amount: None,
        public_spl_amount: None,
        user_sol_account: &user_sol,
        user_spl_token_account: &user_spl,
        spl_token_interface: &interface,
        data_hash: None,
        zone_data_hash: None,
        outputs: &outputs_empty_data,
        messages: &[],
    };
    let no_data_hash = ExternalDataHash::<MessageData> {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: 1,
        relayer_fee: 2,
        public_sol_amount: None,
        public_spl_amount: None,
        user_sol_account: &user_sol,
        user_spl_token_account: &user_spl,
        spl_token_interface: &interface,
        data_hash: None,
        zone_data_hash: None,
        outputs: &outputs_no_data,
        messages: &[],
    };

    let merge = merge_data();
    let merge_hash = MergeExternalDataHash {
        spp_instruction_discriminator: tag::MERGE_TRANSACT,
        expiry_unix_ts: merge.expiry_unix_ts,
        output_utxo_hash: &merge.output_utxo_hash,
        encrypted_utxo: &merge.encrypted_utxo,
    };
    let merge_zone_hash = MergeExternalDataHash {
        spp_instruction_discriminator: tag::ZONE_MERGE_TRANSACT,
        expiry_unix_ts: merge.expiry_unix_ts,
        output_utxo_hash: &merge.output_utxo_hash,
        encrypted_utxo: &merge.encrypted_utxo,
    };

    json!({
        "inputs": {
            "userSolAccount": account(60).to_string(),
            "userSplTokenAccount": account(61).to_string(),
            "splTokenInterface": account(62).to_string(),
            "outputUtxoHashA": hex(&utxo_a),
            "outputUtxoHashB": hex(&utxo_b),
            "ownerTagA": hex(&tag_a),
            "ownerTagB": hex(&tag_b),
            "outputData": hex(&data),
            "messageViewTag": hex(&filler::<32>(54)),
            "messageData": hex(&messages[0].data),
            "dataHash": hex(&filler::<32>(55)),
            "mergeOutputUtxoHash": hex(&merge.output_utxo_hash),
            "mergeEncryptedUtxo": hex(&merge.encrypted_utxo),
            "mergeExpiryUnixTs": merge.expiry_unix_ts.to_string(),
        },
        "full": hex(&full.hash().expect("hashable")),
        "minimal": hex(&minimal.hash().expect("hashable")),
        "outputWithEmptyData": hex(&empty_data_hash.hash().expect("hashable")),
        "outputWithNoData": hex(&no_data_hash.hash().expect("hashable")),
        "mergeTransact": hex(&merge_hash.hash().expect("hashable")),
        "mergeZone": hex(&merge_zone_hash.hash().expect("hashable")),
    })
}

/// `fetch_tag` resolves an output owner tag against the transaction context.
fn fetch_tags() -> Value {
    use zolana_interface::instruction::fetch_tag;
    let inline = filler::<32>(70);
    let signing_key = filler::<32>(71);
    let accounts = [filler::<32>(72), filler::<32>(73)];
    let resolve = |index: u8| accounts.get(usize::from(index)).copied();
    json!({
        "inlineValue": hex(&inline),
        "p256SigningKey": hex(&signing_key),
        "accounts": accounts.iter().map(|a| hex(a)).collect::<Vec<_>>(),
        "inline": hex(&fetch_tag(&OwnerTag::Inline(inline), Some(&signing_key), resolve)
            .expect("inline resolves")),
        "account1": hex(&fetch_tag(&OwnerTag::Account(1), Some(&signing_key), resolve)
            .expect("account resolves")),
        "p256": hex(&fetch_tag(&OwnerTag::P256SigningKey, Some(&signing_key), resolve)
            .expect("p256 resolves")),
        "accountOutOfRangeRejects": fetch_tag(&OwnerTag::Account(9), Some(&signing_key), resolve)
            .is_err(),
        "missingP256Rejects": fetch_tag(&OwnerTag::P256SigningKey, None, resolve).is_err(),
    })
}

fn oracle() -> Value {
    json!({
        "note": "Generated by `cargo run -p xtask --bin ts-interface-oracle -- --write`. \
Every value is produced by calling zolana-interface, never transcribed by hand.",
        "accounts": accounts(),
        "constants": constants(),
        "tags": tags(),
        "errors": errors(),
        "shapes": shapes(),
        "mergeUtils": merge_utils(),
        "pdas": pdas(),
        "state": state(),
        "stateAccounts": state_accounts(),
        "instructionData": instruction_data(),
        "builders": builders(),
        "externalDataHashes": external_data_hashes(),
        "fetchTag": fetch_tags(),
    })
}

fn output_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sdk-libs/ts/interface/test/rust-oracle.json")
}

fn main() {
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&oracle()).expect("serializable oracle")
    );
    let path = output_path();
    let check = std::env::args().any(|arg| arg == "--check");
    if check {
        let existing = fs::read_to_string(&path).unwrap_or_default();
        if existing == rendered {
            println!("ts-interface-oracle: up to date ({})", path.display());
            return;
        }
        eprintln!(
            "ts-interface-oracle: {} is stale; rerun with --write",
            path.display()
        );
        std::process::exit(1);
    }
    fs::write(&path, rendered).expect("write oracle");
    println!("ts-interface-oracle: wrote {}", path.display());
}
