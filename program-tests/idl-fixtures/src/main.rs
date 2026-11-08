//! Exports independent Rust wire fixtures consumed by the IDL tests.
use borsh::BorshSerialize;
use serde_json::{json, Value};
use solana_address::Address;
use spr_event::{EventKind, GeneralEvent, Input, OutputUtxo, SplTransfer};
use spr_interface::{
    instruction::{instruction_data::*, tag},
    state::{cache::CacheAccount, ProtocolConfig, RingConfig, SplAssetCounter, SplAssetRegistry},
    verifying_keys::{
        AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CacheWrite, EddsaProofData,
    },
};
use spr_user_registry_interface::{
    instruction::{RegisterData, SetMergeEncryptionData, UpdateKeysData},
    state::{MergeEncryptionScheme, UserRecord},
};
use std::{path::PathBuf, process::Command};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn a(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}
fn b<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).unwrap()
}
fn ix(program: &str, name: &str, tag: u8, body: Vec<u8>, expected: Value) -> Value {
    let mut bytes = vec![tag];
    bytes.extend(body);
    json!({"program": program, "name": name, "tag": tag, "hex": hex(&bytes), "expected": expected})
}
fn spp(name: &str, tag: u8, body: Vec<u8>, expected: Value) -> Value {
    ix("shieldedPool", name, tag, body, expected)
}
fn transact(circuit: CircuitId) -> TransactIxData {
    let ciphertext = b(&spr_event::OutputDataEncoding::Encrypted(
        [vec![3], vec![2; 33], vec![9; 50]].concat(),
    ));
    TransactIxData {
        expiry_unix_ts: 1800000000,
        private_tx_hash: [8; 32],
        circuit,
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![InputUtxo {
            nullifier_hash: [4; 32],
            tree_index: 0,
        }],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 11,
            nullifier_tree_root_index: 7,
        }],
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![
            TransactOutput {
                utxo_hash: [5; 32],
                owner_tag: OwnerTag::Account(0),
                data: Some(ciphertext.clone()),
            },
            TransactOutput {
                utxo_hash: [6; 32],
                owner_tag: OwnerTag::Account(0),
                data: None,
            },
            TransactOutput {
                utxo_hash: [7; 32],
                owner_tag: OwnerTag::Inline([22; 32]),
                data: Some(ciphertext),
            },
        ],
        messages: vec![spr_event::MessageData {
            view_tag: [10; 32],
            data: vec![11; 300],
        }],
    }
}
fn merge() -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: 42,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [12; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [14; 16],
            ciphertext: [[15; 32], [16; 32], [17; 32]],
        },
        private_tx_hash: [13; 32],
        nullifiers: (0..8).map(|i| [i; 32]).collect(),
        utxo_tree_root_index: 20,
        nullifier_tree_root_index: 30,
        cache_slot: None,
    }
}
fn fixtures(source_commit: &str) -> Value {
    let mut instructions = vec![
        spp(
            "createProtocolConfig",
            tag::CREATE_PROTOCOL_CONFIG,
            bytemuck::bytes_of(&CreateProtocolConfigData {
                protocol_authority: a(1),
                tree_creation_authority: a(2),
                tree_creation_is_permissionless: 1,
                forester_authority: a(3),
                ring_creation_authority: a(4),
                ring_activation_is_permissionless: 0,
                spl_interface_creation_is_permissionless: 1,
                fee_authority: a(5),
            })
            .to_vec(),
            json!({"protocolAuthority":a(1).to_string(),"foresterAuthority":a(3).to_string(),"feeAuthority":a(5).to_string(),"splInterfaceCreationIsPermissionless":1}),
        ),
        spp(
            "updateProtocolConfig",
            tag::UPDATE_PROTOCOL_CONFIG,
            b(&UpdateProtocolConfigData::TreeCreationPermissionless(true)),
            json!({"variant":"treeCreationPermissionless","value":true}),
        ),
        spp(
            "createTree",
            tag::CREATE_TREE,
            b(&CreateTreeData {
                tree_id: 513,
                nullifier_params: spr_tree::NullifierTreeInitParams {
                    input_queue_batch_size: 1000,
                    input_queue_zkp_batch_size: 250,
                    height: 32,
                },
                fees: spr_tree::TreeFeeSchedule {
                    fee_per_tree: 11,
                    append_reimbursement: 12,
                    close_reimbursement: 13,
                },
            }),
            json!({"treeId":513,"nullifierParams":{"inputQueueBatchSize":"1000","height":32},"fees":{"closeReimbursement":"13"}}),
        ),
        spp(
            "setTreeFees",
            tag::SET_TREE_FEES,
            b(&spr_tree::TreeFeeSchedule {
                fee_per_tree: 11,
                append_reimbursement: 12,
                close_reimbursement: 13,
            }),
            json!({"feePerTree":"11","closeReimbursement":"13"}),
        ),
        spp(
            "claimTreeLamports",
            tag::CLAIM_TREE_LAMPORTS,
            vec![],
            Value::Null,
        ),
        spp(
            "closeNullifierPdas",
            tag::CLOSE_NULLIFIER_PDAS,
            vec![],
            Value::Null,
        ),
        spp(
            "setRingActivation",
            tag::SET_RING_ACTIVATION,
            b(&SetRingActivationData {
                activated: 1,
                ring_authority_transact_is_enabled: 0,
            }),
            json!({"activated":1,"ringAuthorityTransactIsEnabled":0}),
        ),
        spp(
            "pauseTree",
            tag::PAUSE_TREE,
            b(&PauseTreeData { paused: 1 }),
            json!({"paused":1}),
        ),
        spp(
            "batchUpdateNullifierTree",
            tag::BATCH_UPDATE_NULLIFIER_TREE,
            b(&BatchUpdateNullifierTreeData {
                new_root: [14; 32],
                old_root: [15; 32],
                zkp_batch_index: 513,
                proof: NullifierTreeProof::default(),
            }),
            json!({"newRoot":hex(&[14;32]),"oldRoot":hex(&[15;32]),"zkpBatchIndex":513}),
        ),
        spp(
            "createAssetCounter",
            tag::CREATE_ASSET_COUNTER,
            vec![],
            Value::Null,
        ),
        spp(
            "createSplInterface",
            tag::CREATE_SPL_INTERFACE,
            vec![],
            Value::Null,
        ),
        spp(
            "createRingConfig",
            tag::CREATE_RING_CONFIG,
            b(&CreateRingConfigData {
                program_id: a(9),
                authority: a(1),
            }),
            json!({"programId":a(9).to_string(),"authority":a(1).to_string()}),
        ),
        spp(
            "updateRingConfig",
            tag::UPDATE_RING_CONFIG,
            b(&UpdateRingConfigData { paused: true }),
            json!({"paused":true}),
        ),
        spp(
            "updateRingConfigOwner",
            tag::UPDATE_RING_CONFIG_OWNER,
            vec![],
            Value::Null,
        ),
    ];
    for (update, variant) in [
        (
            UpdateProtocolConfigData::ProtocolAuthority(a(5)),
            "protocolAuthority",
        ),
        (
            UpdateProtocolConfigData::TreeCreationAuthority(a(5)),
            "treeCreationAuthority",
        ),
        (
            UpdateProtocolConfigData::ForesterAuthority(a(5)),
            "foresterAuthority",
        ),
        (
            UpdateProtocolConfigData::RingCreationAuthority(a(5)),
            "ringCreationAuthority",
        ),
        (UpdateProtocolConfigData::FeeAuthority(a(5)), "feeAuthority"),
    ] {
        instructions.push(spp(
            "updateProtocolConfig",
            tag::UPDATE_PROTOCOL_CONFIG,
            b(&update),
            json!({"variant":variant,"value":a(5).to_string()}),
        ));
    }
    for (update, variant) in [
        (
            UpdateProtocolConfigData::RingActivationPermissionless(false),
            "ringActivationPermissionless",
        ),
        (
            UpdateProtocolConfigData::SplInterfaceCreationPermissionless(false),
            "splInterfaceCreationPermissionless",
        ),
    ] {
        instructions.push(spp(
            "updateProtocolConfig",
            tag::UPDATE_PROTOCOL_CONFIG,
            b(&update),
            json!({"variant":variant,"value":false}),
        ));
    }
    let deposit = DepositIxData {
        assets: vec![
            DepositAssetKind::Sol,
            DepositAssetKind::Spl {
                spl_interface_bump: 254,
            },
        ],
        deposits: vec![
            DepositEntry {
                asset_index: 0,
                view_tag: [22; 32],
                owner: [23; 32],
                amount: 1234567890,
                memo: Some(b"<b>public memo</b>".to_vec()),
            },
            DepositEntry {
                asset_index: 1,
                view_tag: [27; 32],
                owner: [28; 32],
                amount: u64::MAX,
                memo: None,
            },
        ],
    };
    instructions.push(spp("deposit", tag::DEPOSIT, deposit.serialize().unwrap(), json!({"assets":[{"variant":"sol"},{"variant":"spl","splInterfaceBump":254}],"deposits":[{"assetIndex":0,"amount":"1234567890","memo":hex(b"<b>public memo</b>")},{"assetIndex":1,"amount":u64::MAX.to_string(),"memo":null}]})));
    let ring_deposit = RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: [30; 32],
            owner_utxo_hash: [31; 32],
            amount: 99,
            ring_data_hash: [32; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [2; 33],
                salt: [3; 16],
                ciphertext: vec![4; 300],
            },
        }],
    };
    instructions.push(spp(
        "ringDeposit",
        tag::RING_DEPOSIT,
        ring_deposit.serialize().unwrap(),
        json!({"deposits":[{"amount":"99","encrypted":{"ciphertext":hex(&vec![4;300])}}]}),
    ));
    for (name, tag, circuit) in [
        (
            "transact",
            tag::TRANSACT,
            CircuitId::ConfidentialSigner(1, 3, 3),
        ),
        (
            "ringTransact",
            tag::RING_TRANSACT,
            CircuitId::ConfidentialRingEddsa(1, 3, 3),
        ),
        (
            "ringAuthorityTransact",
            tag::RING_AUTHORITY_TRANSACT,
            CircuitId::RingAuthority(1, 3, 3),
        ),
    ] {
        instructions.push(spp(name,tag,transact(circuit).serialize().unwrap(),json!({"expiryUnixTs":"1800000000","inputs":[{"treeIndex":0}],"treeContexts":[{"nullifierTreeRootIndex":7,"utxoTreeRootIndex":11}],"outputs":[{"ownerTag":{"variant":"account","index":0}},{"data":null},{"ownerTag":{"variant":"inline","value":hex(&[22;32])}}],"messages":[{"data":hex(&vec![11;300])}]})));
    }
    for present in [false, true] {
        let circuit = CircuitId::AnonymousRingEddsa(
            1,
            3,
            3,
            AnonymousRingEddsaProofData {
                bsb22_commitment: Bsb22Commitment {
                    commitment: [35; 32],
                    commitment_pok: [36; 32],
                },
                default_owner_tag: present.then_some([37; 32]),
            },
        );
        instructions.push(spp("ringTransact",tag::RING_TRANSACT,transact(circuit).serialize().unwrap(),json!({"circuit":{"variant":"anonymousRingEddsa","bsb22Commitment":{"commitment":hex(&[35;32])},"defaultOwnerTag":if present {json!(hex(&[37;32]))} else {Value::Null}},"privateTxHash":hex(&[8;32]),"messages":[{"data":hex(&vec![11;300])}]})));
    }
    let mut settlements = transact(CircuitId::ConfidentialSigner(1, 3, 3));
    settlements.interface_transfers = vec![
        InterfaceTransfer::SolDeposit { amount: 17 },
        InterfaceTransfer::SolWithdrawal { amount: 18 },
        InterfaceTransfer::SplDeposit {
            amount: 9007199254740993,
            spl_interface_bump: 254,
        },
        InterfaceTransfer::SplWithdrawal {
            amount: 19,
            spl_interface_bump: 253,
        },
    ];
    instructions.push(spp("transact",tag::TRANSACT,settlements.serialize().unwrap(),json!({"interfaceTransfers":[{"variant":"solDeposit","amount":"17"},{"variant":"solWithdrawal","amount":"18"},{"variant":"splDeposit","amount":"9007199254740993","splInterfaceBump":254},{"variant":"splWithdrawal","amount":"19","splInterfaceBump":253}]})));
    instructions.push(spp(
        "mergeTransact",
        tag::MERGE_TRANSACT,
        merge().serialize().unwrap(),
        json!({"outputEncryption":{"variant":"poseidonCtrV1","salt":hex(&[14;16]),"ciphertext":[hex(&[15;32]),hex(&[16;32]),hex(&[17;32])]},"utxoTreeRootIndex":20,"nullifierTreeRootIndex":30,"cacheSlot":null}),
    ));
    instructions.push(spp(
        "ringMergeTransact",
        tag::RING_MERGE_TRANSACT,
        MergeRingIxData {
            output_ring_data_hash: [38; 32],
            merge: merge(),
        }
        .serialize()
        .unwrap(),
        json!({"outputRingDataHash":hex(&[38;32]),"merge":{"outputEncryption":{"variant":"poseidonCtrV1"},"expiryUnixTs":"42","cacheSlot":null}}),
    ));
    let mut write_slots = CacheAccess::NO_WRITES;
    write_slots[0] = CacheWrite {
        output: 0,
        slot: 35,
    };
    let access = CacheAccess {
        read_bitmap: 1u64 << 35,
        write_slots,
    };
    let anonymous = AnonymousRingEddsaProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [35; 32],
            commitment_pok: [36; 32],
        },
        default_owner_tag: Some([37; 32]),
    };
    let eddsa = EddsaProofData {
        bsb22_commitment: anonymous.bsb22_commitment,
        owner_pk: [38; 32],
    };
    for (circuit, variant) in [
        (
            CircuitId::ConfidentialSignerCached(1, 3, 3, access),
            "confidentialSignerCached",
        ),
        (
            CircuitId::ConfidentialRingEddsaCached(1, 3, 3, access),
            "confidentialRingEddsaCached",
        ),
        (
            CircuitId::AnonymousRingEddsaCached(1, 3, 3, anonymous, access),
            "anonymousRingEddsaCached",
        ),
        (
            CircuitId::ConfidentialEddsa(1, 3, 3, eddsa),
            "confidentialEddsa",
        ),
        (
            CircuitId::ConfidentialEddsaCached(1, 3, 3, eddsa, access),
            "confidentialEddsaCached",
        ),
    ] {
        let mut expected = json!({"variant":variant,"inputs":1,"outputs":3,"publicAssetSlots":3});
        if circuit.cache_access().is_some() {
            expected["cacheAccess"] = json!({"readBitmap":(1u64 << 35).to_string(),"writeSlots":write_slots.iter().map(|slot|json!({"output":slot.output,"slot":slot.slot})).collect::<Vec<_>>()});
        }
        if circuit.bsb22_commitment().is_some() {
            expected["bsb22Commitment"] =
                json!({"commitment":hex(&[35;32]),"commitmentPok":hex(&[36;32])});
        }
        if circuit.eddsa_owner_pk().is_some() {
            expected["ownerPk"] = json!(hex(&[38; 32]));
        }
        if circuit.default_owner_tag().is_some() {
            expected["defaultOwnerTag"] = json!(hex(&[37; 32]));
        }
        instructions.push(spp(
            "transact",
            tag::TRANSACT,
            transact(circuit).serialize().unwrap(),
            json!({"circuit":expected}),
        ));
    }
    for cache_slot in [Some(0), Some(35)] {
        let mut cached_merge = merge();
        cached_merge.cache_slot = cache_slot;
        instructions.push(spp(
            "mergeTransact",
            tag::MERGE_TRANSACT,
            cached_merge.serialize().unwrap(),
            json!({"cacheSlot":cache_slot}),
        ));
        instructions.push(spp(
            "ringMergeTransact",
            tag::RING_MERGE_TRANSACT,
            MergeRingIxData {
                output_ring_data_hash: [38; 32],
                merge: cached_merge,
            }
            .serialize()
            .unwrap(),
            json!({"merge":{"cacheSlot":cache_slot}}),
        ));
    }
    for expires_at in [i64::MIN, -42, 1_800_000_000, i64::MAX] {
        let create = CreateCacheData {
            write_authority: a(58),
            nonce: u64::MAX,
            tree_id: 513,
            expires_at,
        };
        instructions.push(spp("createCache",tag::CREATE_CACHE,wincode::serialize(&create).unwrap(),json!({"writeAuthority":a(58).to_string(),"nonce":u64::MAX.to_string(),"treeId":513,"expiresAt":expires_at.to_string()})));
    }
    instructions.push(spp("closeCache", tag::CLOSE_CACHE, vec![], Value::Null));
    let general = GeneralEvent {
        inputs: vec![Input {
            tree: [39; 32],
            input_queue_seq: 9007199254740993,
            nullifier: [40; 32],
        }],
        outputs: vec![OutputUtxo {
            view_tag: [41; 32],
            utxo_hash: [42; 32],
            data: vec![43; 300],
        }],
        messages: vec![spr_event::MessageData {
            view_tag: [44; 32],
            data: vec![45; 300],
        }],
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        first_output_leaf_index: 52,
        output_tree: [46; 32],
        spl_transfers: vec![
            SplTransfer {
                is_deposit: true,
                amount: 53,
                asset: None,
            },
            SplTransfer {
                is_deposit: false,
                amount: 54,
                asset: Some([47; 32]),
            },
        ],
    };
    let bytes = spr_event::encode_event_instruction(EventKind::Deposit, &general);
    instructions.push(spp("emitEvent", tag::EMIT_EVENT, bytes[1..].to_vec(), json!({"variant":"deposit","event":{"inputs":[{"inputQueueSeq":"9007199254740993"}],"outputs":[{"data":hex(&vec![43;300])}],"firstOutputLeafIndex":"52"}})));
    let input_trees = vec![spr_event::InputTreeSequence {
        tree: [39; 32],
        first_input_queue_seq: 9007199254740993,
    }];
    let bytes = spr_event::encode_event_instruction(
        EventKind::Transact,
        &spr_event::TransactEvent {
            input_trees: input_trees.clone(),
            output_tree: [46; 32],
            first_output_leaf_index: 52,
        },
    );
    instructions.push(spp("emitEvent", tag::EMIT_EVENT, bytes[1..].to_vec(), json!({"variant":"transact","event":{"inputTrees":[{"firstInputQueueSeq":"9007199254740993"}],"firstOutputLeafIndex":"52"}})));
    let bytes = spr_event::encode_event_instruction(
        EventKind::Merge,
        &spr_event::MergeEvent {
            input_trees,
            output_tree: [46; 32],
            output_leaf_index: 52,
            output_view_tag: [41; 32],
        },
    );
    instructions.push(spp(
        "emitEvent",
        tag::EMIT_EVENT,
        bytes[1..].to_vec(),
        json!({"variant":"merge","event":{"outputLeafIndex":"52","outputViewTag":hex(&[41;32])}}),
    ));
    let batch = spr_event::NullifierTreeUpdateEvent {
        merkle_tree_pubkey: [48; 32],
        zkp_batch_size: 250,
        old_next_index: 55,
        start_sequence_number: 56,
        first_root_index: 57,
        num_update: 2,
        first_zkp_batch_index: 58,
        new_root: [49; 32],
    };
    let bytes = spr_event::encode_event_instruction(EventKind::NullifierTreeUpdate, &batch);
    instructions.push(spp("emitEvent",tag::EMIT_EVENT,bytes[1..].to_vec(),json!({"variant":"nullifierTreeUpdate","event":{"zkpBatchSize":250,"oldNextIndex":"55","numUpdate":2,"newRoot":hex(&[49;32])}})));
    instructions.extend([
        ix(
            "userRegistry",
            "register",
            0,
            b(&RegisterData {
                nullifier_pubkey: [50; 32],
                viewing_pubkey: [3; 33],
            }),
            json!({"nullifierPubkey":hex(&[50;32]),"viewingPubkey":hex(&[3;33])}),
        ),
        ix(
            "userRegistry",
            "setMergeEncryption",
            1,
            b(&SetMergeEncryptionData {
                scheme: MergeEncryptionScheme::PoseidonCtrV1,
            }),
            json!({"scheme":{"variant":"poseidonCtrV1"}}),
        ),
        ix(
            "userRegistry",
            "updateKeys",
            2,
            b(&UpdateKeysData {
                viewing_pubkey: [4; 33],
            }),
            json!({"viewingPubkey":hex(&[4;33])}),
        ),
    ]);
    let mut accounts = vec![
        json!({"program":"shieldedPool","name":"ringConfig","hex":hex(bytemuck::bytes_of(&RingConfig {discriminator:4,authority:a(1),program_id:a(9),ring_authority_transact_is_enabled:1,paused:0,activated:1,bump:254})),"expected":{"programId":a(9).to_string(),"activated":1,"bump":254}}),
        json!({"program":"shieldedPool","name":"protocolConfig","hex":hex(bytemuck::bytes_of(&ProtocolConfig {discriminator:3,protocol_authority:a(1),tree_creation_authority:a(2),forester_authority:a(3),ring_creation_authority:a(4),tree_creation_is_permissionless:1,ring_activation_is_permissionless:0,spl_interface_creation_is_permissionless:1,fee_authority:a(5),next_tree_id:513})),"expected":{"foresterAuthority":a(3).to_string(),"feeAuthority":a(5).to_string(),"splInterfaceCreationIsPermissionless":1}}),
        json!({"program":"shieldedPool","name":"splAssetRegistry","hex":hex(&SplAssetRegistry::account_bytes(a(55),2)),"expected":{"mint":a(55).to_string(),"assetId":"2"}}),
        json!({"program":"shieldedPool","name":"splAssetCounter","hex":hex(bytemuck::bytes_of(&SplAssetCounter {discriminator:6,reserved:[0;7],next_id:123})),"expected":{"nextId":"123"}}),
    ];
    for (scheme, variant) in [
        (MergeEncryptionScheme::Disabled, "disabled"),
        (MergeEncryptionScheme::PoseidonCtrV1, "poseidonCtrV1"),
    ] {
        let record = UserRecord {
            owner: a(21),
            bump: 253,
            nullifier_pubkey: [56; 32],
            viewing_pubkey: [3; 33],
            merge_encryption: scheme,
        };
        let mut bytes = vec![UserRecord::DISCRIMINATOR];
        bytes.extend(b(&record));
        assert_eq!(bytes.len(), UserRecord::SIZE);
        accounts.push(json!({"program":"userRegistry","name":"userRecord","hex":hex(&bytes),"expected":{"owner":a(21).to_string(),"nullifierPubkey":hex(&[56;32]),"mergeEncryption":{"variant":variant}}}));
        instructions.push(ix(
            "userRegistry",
            "setMergeEncryption",
            1,
            b(&SetMergeEncryptionData { scheme }),
            json!({"scheme":{"variant":variant}}),
        ));
    }
    let cache = CacheAccount {
        discriminator: 7,
        bump: 252,
        tree_id: 513u16.to_le_bytes(),
        expires_at: (-42i64).to_le_bytes(),
        rent_sponsor: a(57),
        write_authority: a(58),
        utxo_hashes: [[59; 32]; 36],
    };
    accounts.push(json!({"program":"shieldedPool","name":"cache","hex":hex(bytemuck::bytes_of(&cache)),"expected":{"bump":252,"treeId":513,"expiresAt":"-42","rentSponsor":a(57).to_string(),"writeAuthority":a(58).to_string(),"utxoHashes":vec![hex(&[59;32]);36]}}));
    let registry_instructions = [
        (
            "register",
            spr_user_registry_interface::instruction::register(
                a(21),
                a(22),
                a(23),
                RegisterData {
                    nullifier_pubkey: [50; 32],
                    viewing_pubkey: [3; 33],
                },
            ),
        ),
        (
            "setMergeEncryption",
            spr_user_registry_interface::instruction::set_merge_encryption(
                a(21),
                a(22),
                MergeEncryptionScheme::Disabled,
            ),
        ),
        (
            "updateKeys",
            spr_user_registry_interface::instruction::update_keys(
                a(21),
                a(22),
                UpdateKeysData {
                    viewing_pubkey: [4; 33],
                },
            ),
        ),
    ];
    let account_metas: Vec<_> = registry_instructions
        .iter()
        .map(|(name, ix)| {
            let accounts: Vec<_> = ix
                .accounts
                .iter()
                .map(|meta| json!({"isWritable":meta.is_writable,"isSigner":meta.is_signer}))
                .collect();
            json!({"program":"userRegistry","name":name,"accounts":accounts})
        })
        .collect();
    json!({"schemaVersion":"1","sourceCommit":source_commit,"instructions":instructions,"accounts":accounts,"accountMetas":account_metas})
}
fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk-libs/ts/fixtures/idl/rust.json")
}
fn main() {
    let write = std::env::args().any(|arg| arg == "--write");
    if write {
        let commit = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(commit.status.success());
        let value = fixtures(String::from_utf8(commit.stdout).unwrap().trim());
        std::fs::write(
            path(),
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        )
        .unwrap();
        println!("Wrote Rust idl fixtures");
    } else {
        check();
    }
}
fn check() {
    let committed: Value = serde_json::from_slice(
        &std::fs::read(path()).expect("Run fixture exporter with --write first"),
    )
    .unwrap();
    assert_eq!(
        fixtures(committed["sourceCommit"].as_str().unwrap()),
        committed,
        "Rust wire fixtures drifted; regenerate and review decoder tests"
    );
    println!("Rust idl fixtures match current serialization");
}
#[cfg(test)]
mod main_test;
