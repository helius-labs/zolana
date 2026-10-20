use solana_address::Address;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use zolana_client::ClientError;
use zolana_event::tag;
use zolana_event_parser::{InstructionGroup, ParsedInstruction};
use zolana_interface::{
    instruction::{CircuitId, InterfaceTransfer, TransactIxData, TransactProof, TreeContext},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use zolana_interface::{
    instruction::{InputUtxo, MessageData, OwnerTag, TransactOutput},
    verifying_keys::{AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CacheWrite},
};
use zolana_transaction::SOL_MINT;

use super::*;

fn ring_invoked_in(groups: &[InstructionGroup], ring: Address) -> Result<bool, AuditError> {
    Ok(!ring_instructions_in(groups, ring)?.is_empty())
}

fn ring_withdrawals_in(
    groups: &[InstructionGroup],
    ring: Address,
) -> Result<Vec<RingWithdrawal>, AuditError> {
    ring_withdrawals_of(&ring_instructions_in(groups, ring)?)
}

const RING: Address = Address::new_from_array([9u8; 32]);
const OTHER: Address = Address::new_from_array([8u8; 32]);
const POOL: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
const SOL: Address = Address::new_from_array(SOL_INTERFACE);
const RECIPIENT: Address = Address::new_from_array([3u8; 32]);
const CPI_AUTHORITY: Address = Address::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
const MINT: Address = Address::new_from_array([4u8; 32]);
const TOKEN_ACCOUNT: Address = Address::new_from_array([5u8; 32]);

fn instruction(program_id: Address, stack_height: u32) -> ParsedInstruction {
    ParsedInstruction::new(program_id, Vec::new(), Vec::new(), stack_height)
}

fn group(outer: Address, inner: &[(Address, u32)]) -> InstructionGroup {
    InstructionGroup {
        outer: instruction(outer, 1),
        inner: inner
            .iter()
            .map(|(program_id, height)| instruction(*program_id, *height))
            .collect(),
    }
}

fn event_data() -> String {
    let event = zolana_event::TransactEvent {
        input_trees: vec![zolana_event::InputTreeSequence {
            tree: zolana_interface::pda::tree(0).to_bytes(),
            first_input_queue_seq: 0,
        }],
        output_tree: zolana_interface::pda::tree(0).to_bytes(),
        first_output_leaf_index: 0,
    };
    bs58::encode(
        [
            vec![tag::EMIT_EVENT, zolana_event::EventKind::Transact as u8],
            borsh::to_vec(&event).unwrap(),
        ]
        .concat(),
    )
    .into_string()
}

#[test]
fn pool_directly_under_the_ring_is_attributed() {
    let groups = [group(RING, &[(POOL, 2), (OTHER, 3)])];
    assert!(ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn only_confirmed_ring_transfer_events_require_auditor_messages() {
    for kind in [tag::RING_TRANSACT, tag::RING_AUTHORITY_TRANSACT] {
        let mut source = instruction(POOL, 2);
        source.data = ring_transact_bytes(Vec::new());
        source.data[0] = kind;
        let mut event = instruction(POOL, 3);
        event.data = bs58::decode(event_data()).into_vec().unwrap();
        let origin = ring_event_origin_in(
            &[InstructionGroup {
                outer: instruction(RING, 1),
                inner: vec![source, event],
            }],
            0,
            RING,
        )
        .unwrap();
        assert!(origin.ring_invoked);
        assert_eq!(
            origin.requires_audit(),
            matches!(kind, tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT)
        );
    }
}

#[test]
fn pool_at_top_level_is_not_attributed() {
    let groups = [group(POOL, &[(OTHER, 2)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn pool_under_an_intermediary_is_not_attributed() {
    let groups = [group(RING, &[(OTHER, 2), (POOL, 3)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn ring_nested_under_another_program_still_signs_for_the_pool() {
    let groups = [group(OTHER, &[(RING, 2), (POOL, 3), (OTHER, 2), (POOL, 3)])];
    assert!(ring_invoked_in(&groups, RING).expect("walk"));
    let groups = [group(OTHER, &[(RING, 2), (OTHER, 2), (POOL, 3)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn stack_height_without_a_parent_is_an_error() {
    let groups = [group(RING, &[(POOL, 4)])];
    assert!(matches!(
        ring_invoked_in(&groups, RING),
        Err(AuditError::InvalidStackHeight(4))
    ));
}

/// A version 0 transaction resolves later account indexes through a lookup
/// table. That list is rejected rather than appended.
#[test]
fn a_lookup_table_is_rejected() {
    let payer = Address::new_from_array([1u8; 32]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 1
                },
                "accountKeys": [payer.to_string(), RING.to_string()],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ],
                "addressTableLookups": []
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        {
                            "programIdIndex": 3,
                            "accounts": [2],
                            "data": ring_transact_data(Vec::new()),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                }
            ],
            "loadedAddresses": {
                "writable": [OTHER.to_string()],
                "readonly": [POOL.to_string()]
            }
        },
        "version": 0
    });
    let transaction: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_value(json).expect("rpc shape");
    let error = confirmed_origin(transaction, 0, RING)
        .map(|origin| origin.ring_invoked)
        .expect_err("lookup table");
    assert!(matches!(
        error,
        AuditError::Client(ClientError::AddressLookupTable)
    ));
}

#[test]
fn event_ordinals_separate_two_origins_in_one_transaction() {
    let payer = Address::new_from_array([1u8; 32]);
    let signature = Signature::from([7u8; 64]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [signature.to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 3
                },
                "accountKeys": [
                    payer.to_string(), RING.to_string(), OTHER.to_string(), POOL.to_string()
                ],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null },
                    { "programIdIndex": 2, "accounts": [0], "data": "", "stackHeight": null }
                ]
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0, 0, 0],
            "postBalances": [0, 0, 0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": ring_transact_data(Vec::new()),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                },
                {
                    "index": 1,
                    "instructions": [
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": ring_transact_data(Vec::new()),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                }
            ]
        }
    });
    let first: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_value(json.clone()).expect("rpc shape");
    let second: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_value(json).expect("rpc shape");

    assert!(confirmed_origin(first, 0, RING)
        .map(|origin| origin.ring_invoked)
        .expect("first origin"));
    assert!(!confirmed_origin(second, 1, RING)
        .map(|origin| origin.ring_invoked)
        .expect("second origin"));
}

/// The settlement walk reads instruction groups, so it needs no confirmed
/// transaction and no RPC.
#[test]
fn withdrawals_read_from_instruction_groups_without_a_transaction() {
    let mut pool = instruction(POOL, 2);
    pool.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 77 }]);
    pool.accounts = vec![Address::default(), SOL, RECIPIENT];
    let groups = [InstructionGroup {
        outer: instruction(RING, 1),
        inner: vec![pool],
    }];

    assert_eq!(
        ring_withdrawals_in(&groups, RING).expect("walk"),
        vec![RingWithdrawal {
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 77,
        }]
    );
}

#[test]
fn cached_settlement_vectors_match_rust_and_exclude_the_cache() {
    let selection = CacheAccess {
        read_bitmap: 1,
        write_slots: CacheAccess::NO_WRITES,
    };
    let circuits = [
        CircuitId::ConfidentialRingEddsaCached(1, 2, 1, selection),
        CircuitId::AnonymousRingEddsaCached(
            1,
            2,
            1,
            AnonymousRingEddsaProofData {
                bsb22_commitment: Bsb22Commitment {
                    commitment: [17; 32],
                    commitment_pok: [18; 32],
                },
                default_owner_tag: Some([19; 32]),
            },
            selection,
        ),
    ];
    let mut writing = circuits;
    for circuit in &mut writing {
        match circuit {
            CircuitId::ConfidentialRingEddsaCached(_, _, _, access)
            | CircuitId::AnonymousRingEddsaCached(_, _, _, _, access) => {
                access.write_slots = CacheAccess::NO_WRITES;
                for (entry, (output, slot)) in access.write_slots.iter_mut().zip([(0, 0), (1, 1)]) {
                    *entry = CacheWrite { output, slot };
                }
            }
            _ => panic!("cached test rail"),
        }
    }
    let circuits: Vec<_> = circuits.into_iter().chain(writing).collect();
    let vectors: Vec<_> = include_str!("../../../../test-vectors/cached_ring_settlement.hex")
        .lines()
        .collect();
    assert_eq!(vectors.len(), circuits.len());
    for (circuit, encoded) in circuits.into_iter().zip(vectors) {
        assert_settlement_vector(circuit, encoded);
    }
}

#[test]
fn anonymous_settlement_vector_matches_rust_and_has_no_cache() {
    let circuit = CircuitId::AnonymousRingEddsa(
        1,
        2,
        1,
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [21; 32],
                commitment_pok: [22; 32],
            },
            default_owner_tag: None,
        },
    );
    assert_settlement_vector(
        circuit,
        include_str!("../../../../test-vectors/anonymous_ring_settlement.hex").trim(),
    );
}

fn assert_settlement_vector(circuit: CircuitId, encoded: &str) {
    let data = TransactIxData {
        expiry_unix_ts: 0,
        private_tx_hash: [1; 32],
        circuit,
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        proof: TransactProof::zeroed(),
        interface_transfers: vec![
            InterfaceTransfer::SolWithdrawal { amount: 7 },
            InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 254,
            },
        ],
        data_hash: Some([4; 32]),
        ring_data_hash: Some([5; 32]),
        outputs: vec![
            TransactOutput {
                utxo_hash: [6; 32],
                owner_tag: OwnerTag::Inline([7; 32]),
                data: Some(vec![8, 9]),
            },
            TransactOutput {
                utxo_hash: [10; 32],
                owner_tag: OwnerTag::Account(1),
                data: None,
            },
        ],
        messages: vec![MessageData {
            view_tag: [11; 32],
            data: vec![12, 13, 14],
        }],
        inputs: vec![InputUtxo {
            nullifier_hash: [20; 32],
            tree_index: 0,
        }],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    };
    let bytes = hex::decode(encoded).expect("pinned wire vector");
    assert_eq!(data.serialize().expect("serialize"), bytes);
    let mut answers = instruction(POOL, 2);
    answers.data = [vec![tag::RING_TRANSACT], bytes].concat();
    answers.accounts = vec![
        OTHER,
        SOL,
        RECIPIENT,
        CPI_AUTHORITY,
        MINT,
        OTHER,
        TOKEN_ACCOUNT,
        OTHER,
    ];
    if let Some(access) = circuit.cache_access() {
        if access.read_bitmap != 0 {
            answers.accounts.push(OTHER);
        }
        if access.writes_cache() {
            answers.accounts.extend([OTHER, OTHER]);
        }
    }
    let mut groups = [InstructionGroup {
        outer: instruction(RING, 1),
        inner: vec![answers],
    }];
    assert_eq!(
        ring_withdrawals_in(&groups, RING).expect("settlement"),
        vec![
            RingWithdrawal {
                recipient: RECIPIENT,
                asset: SOL_MINT,
                amount: 7
            },
            RingWithdrawal {
                recipient: TOKEN_ACCOUNT,
                asset: MINT,
                amount: 9
            },
        ]
    );
    groups
        .first_mut()
        .expect("group")
        .inner
        .first_mut()
        .expect("instruction")
        .accounts
        .truncate(7);
    assert!(matches!(
        ring_withdrawals_in(&groups, RING),
        Err(AuditError::SettlementAccounts)
    ));
}

#[test]
fn withdrawals_of_a_ring_that_did_not_sign_are_not_reported() {
    let mut pool = instruction(POOL, 2);
    pool.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 77 }]);
    pool.accounts = vec![Address::default(), SOL, RECIPIENT];
    let groups = [InstructionGroup {
        outer: instruction(OTHER, 1),
        inner: vec![pool],
    }];

    assert!(ring_withdrawals_in(&groups, RING).expect("walk").is_empty());
}

fn ring_transact_bytes(interface_transfers: Vec<InterfaceTransfer>) -> Vec<u8> {
    let data = TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialRingEddsa(0, 0, 3),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    };
    let mut encoded = vec![tag::RING_TRANSACT];
    encoded.extend_from_slice(&data.serialize().expect("serialize"));
    encoded
}

fn ring_transact_data(interface_transfers: Vec<InterfaceTransfer>) -> String {
    bs58::encode(ring_transact_bytes(interface_transfers)).into_string()
}

/// A ring transact CPI with `accounts` as its pool-instruction account indices.
fn withdrawing_transaction(
    interface_transfers: Vec<InterfaceTransfer>,
    accounts: Vec<u8>,
) -> EncodedConfirmedTransactionWithStatusMeta {
    let payer = Address::new_from_array([1u8; 32]);
    let tree = Address::new_from_array([2u8; 32]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 6
                },
                "accountKeys": [
                    payer.to_string(),
                    RING.to_string(),
                    POOL.to_string(),
                    Address::default().to_string(),
                    OTHER.to_string(),
                    tree.to_string(),
                    SOL.to_string(),
                    RECIPIENT.to_string(),
                    CPI_AUTHORITY.to_string(),
                    MINT.to_string(),
                    TOKEN_ACCOUNT.to_string()
                ],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ]
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        {
                            "programIdIndex": 2,
                            "accounts": accounts,
                            "data": ring_transact_data(interface_transfers),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 2,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                }
            ]
        }
    });
    serde_json::from_value(json).expect("rpc shape")
}

/// The recipient is the account following `SOL_INTERFACE` in the settlement
/// accounts appended to the pool instruction.
#[test]
fn sol_withdrawal_reports_its_recipient_and_amount() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![InterfaceTransfer::SolWithdrawal { amount: 4_200 }],
            vec![0, 5, 5, 2, 3, 4, 6, 7],
        ),
        0,
        RING,
    )
    .expect("walk");

    assert!(origin.ring_invoked);
    assert_eq!(
        origin.withdrawals,
        vec![RingWithdrawal {
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 4_200,
        }]
    );
}

/// The credited token account and the mint sit at indices 3 and 1 of the SPL
/// settlement group.
#[test]
fn spl_withdrawal_reports_its_mint_and_token_account() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 42,
            }],
            vec![0, 5, 5, 2, 3, 8, 9, 4, 10, 4],
        ),
        0,
        RING,
    )
    .expect("walk");

    assert_eq!(
        origin.withdrawals,
        vec![RingWithdrawal {
            recipient: TOKEN_ACCOUNT,
            asset: MINT,
            amount: 9,
        }]
    );
}

/// A preceding SPL withdrawal shifts the SOL settlement group by five accounts.
#[test]
fn mixed_spl_and_sol_legs_are_both_reported() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![
                InterfaceTransfer::SplWithdrawal {
                    amount: 9,
                    spl_interface_bump: 42,
                },
                InterfaceTransfer::SolWithdrawal { amount: 11 },
            ],
            vec![0, 5, 5, 2, 3, 8, 9, 4, 10, 4, 6, 7],
        ),
        0,
        RING,
    )
    .expect("walk");

    assert_eq!(
        origin.withdrawals,
        vec![
            RingWithdrawal {
                recipient: TOKEN_ACCOUNT,
                asset: MINT,
                amount: 9,
            },
            RingWithdrawal {
                recipient: RECIPIENT,
                asset: SOL_MINT,
                amount: 11,
            }
        ]
    );
}

#[test]
fn spl_settlement_group_without_the_cpi_authority_is_an_error() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 42,
            }],
            vec![0, 5, 5, 2, 3, 4, 9, 4, 10, 4],
        ),
        0,
        RING,
    );

    assert!(matches!(origin, Err(AuditError::SettlementAccounts)));
}

#[test]
fn a_confirmed_response_for_another_signature_is_rejected() {
    let result = confirmed_origin_for(
        Signature::from([7; 64]),
        withdrawing_transaction(Vec::new(), Vec::new()),
        0,
        RING,
    );
    assert!(matches!(result, Err(AuditError::Unavailable { .. })));
}

#[test]
fn a_failed_transaction_grants_no_origin() {
    let mut response =
        serde_json::to_value(withdrawing_transaction(Vec::new(), Vec::new())).unwrap();
    response["meta"]["err"] = serde_json::json!("AccountNotFound");
    let result = confirmed_origin_for(
        Signature::from([6; 64]),
        serde_json::from_value(response).unwrap(),
        0,
        RING,
    );
    assert!(matches!(
        result,
        Err(AuditError::Client(ClientError::TransactionFailed(_)))
    ));
}

#[test]
fn shaped_policy_outer_tags_preserve_confirmed_ring_origin() {
    for (outer_tag, inner_tag) in [
        (
            custom_ring_interface::tag::TRANSACT_SHAPED,
            tag::RING_TRANSACT,
        ),
        (
            custom_ring_interface::tag::DELEGATE_TRANSACT_SHAPED,
            tag::RING_AUTHORITY_TRANSACT,
        ),
        (
            custom_ring_interface::tag::TRANSACT_SHAPED_SUBTREE,
            tag::RING_TRANSACT,
        ),
        (
            custom_ring_interface::tag::DELEGATE_TRANSACT_SHAPED_SUBTREE,
            tag::RING_AUTHORITY_TRANSACT,
        ),
    ] {
        let mut outer = instruction(RING, 1);
        outer.data = vec![outer_tag];
        let mut source = instruction(POOL, 2);
        source.data = ring_transact_bytes(Vec::new());
        source.data[0] = inner_tag;
        let mut event = instruction(POOL, 3);
        event.data = bs58::decode(event_data()).into_vec().unwrap();
        let groups = [InstructionGroup {
            outer,
            inner: vec![source, event],
        }];
        assert!(ring_event_origin_in(&groups, 0, RING).unwrap().ring_invoked);
        assert!(
            !ring_event_origin_in(&groups, 0, OTHER)
                .unwrap()
                .ring_invoked
        );
    }
}

fn confirmed_transfer_fixture() -> (InstructionGroup, ShieldedTransaction) {
    use zolana_event::{encode_event_instruction, EventKind, InputTreeSequence, TransactEvent};
    use zolana_transaction::{OutputContext, OutputSlot};

    let key = zolana_keypair::X25519Keypair::from_bytes(&[7; 32]).pubkey();
    let mut data = TransactIxData::deserialize(&ring_transact_bytes(Vec::new())[1..]).unwrap();
    data.tx_viewing_pk = *key.as_bytes();
    data.salt = [0; 16];
    data.inputs = vec![
        InputUtxo {
            nullifier_hash: [20; 32],
            tree_index: 0,
        },
        InputUtxo {
            nullifier_hash: [21; 32],
            tree_index: 0,
        },
    ];
    data.outputs = vec![
        TransactOutput {
            utxo_hash: [6; 32],
            owner_tag: OwnerTag::Inline([7; 32]),
            data: Some(vec![8, 9]),
        },
        TransactOutput {
            utxo_hash: [10; 32],
            owner_tag: OwnerTag::Account(1),
            data: None,
        },
    ];
    data.messages = vec![MessageData {
        view_tag: [11; 32],
        data: vec![12, 13, 14],
    }];
    let event = TransactEvent {
        input_trees: vec![InputTreeSequence {
            tree: zolana_interface::pda::tree(1).to_bytes(),
            first_input_queue_seq: 5,
        }],
        output_tree: zolana_interface::pda::tree(3).to_bytes(),
        first_output_leaf_index: 42,
    };
    let group = InstructionGroup {
        outer: instruction(RING, 1),
        inner: vec![
            ParsedInstruction::new(
                POOL,
                vec![RING, RECIPIENT],
                [vec![tag::RING_TRANSACT], data.serialize().unwrap()].concat(),
                2,
            ),
            ParsedInstruction::new(
                POOL,
                vec![],
                encode_event_instruction(EventKind::Transact, &event),
                3,
            ),
        ],
    };
    let indexed = ShieldedTransaction {
        slot: 99,
        tx_signature: Signature::from([6; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(key),
        salt: None,
        output_slots: vec![
            OutputSlot {
                view_tag: [7; 32],
                output_context: OutputContext {
                    hash: [6; 32],
                    tree_id: 3,
                    leaf_index: 42,
                },
                payload: vec![8, 9],
            },
            OutputSlot {
                view_tag: RECIPIENT.to_bytes(),
                output_context: OutputContext {
                    hash: [10; 32],
                    tree_id: 3,
                    leaf_index: 43,
                },
                payload: vec![],
            },
        ],
        messages: data.messages,
        nullifiers: vec![[20; 32], [21; 32]],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    (group, indexed)
}

#[test]
fn confirmed_event_binds_every_indexed_audit_and_recovery_field() {
    let (group, indexed) = confirmed_transfer_fixture();
    let origin = ring_event_origin_in(&[group], 0, RING).unwrap();
    let mut valid = indexed.clone();
    origin.bind_transaction(&mut valid, RING).unwrap();
    assert_eq!(
        valid.salt,
        Some([0; 16]),
        "normalize only the confirmed zero salt"
    );
    type Mutation = (&'static str, fn(&mut ShieldedTransaction));
    let mutations: &[Mutation] = &[
        ("kind", |tx| tx.proofless = true),
        ("viewing key", |tx| tx.tx_viewing_pk = None),
        ("salt", |tx| tx.salt = Some([1; 16])),
        ("missing message", |tx| tx.messages.clear()),
        ("message tag", |tx| tx.messages[0].view_tag[0] ^= 1),
        ("message data", |tx| tx.messages[0].data[0] ^= 1),
        ("nullifier", |tx| tx.nullifiers[0][0] ^= 1),
        ("nullifier order", |tx| tx.nullifiers.swap(0, 1)),
        ("nullifier count", |tx| tx.nullifiers.push([22; 32])),
        ("output count", |tx| {
            tx.output_slots.pop();
        }),
        ("output tag", |tx| tx.output_slots[0].view_tag[0] ^= 1),
        ("output commitment", |tx| {
            tx.output_slots[0].output_context.hash[0] ^= 1
        }),
        ("output payload", |tx| tx.output_slots[0].payload[0] ^= 1),
        ("output tree", |tx| {
            tx.output_slots[0].output_context.tree_id += 1
        }),
        ("output position", |tx| {
            tx.output_slots[1].output_context.leaf_index += 1
        }),
        ("ring", |tx| tx.ring_program_id = Some(OTHER)),
    ];
    for (name, mutate) in mutations {
        let mut forged = indexed.clone();
        mutate(&mut forged);
        assert!(
            matches!(
                origin.bind_transaction(&mut forged, RING),
                Err(AuditError::ConfirmedEventMismatch)
            ),
            "{name}"
        );
    }
}

#[test]
fn confirmed_event_wire_fixture_matches_the_shared_parser() {
    let (group, indexed) = confirmed_transfer_fixture();
    check_event_wire_fixture("confirmed-event", group, indexed);
    let (group, indexed) = confirmed_deposit_fixture();
    check_event_wire_fixture("confirmed-deposit-event", group, indexed);
    let (group, indexed) = confirmed_merge_fixture();
    check_event_wire_fixture("confirmed-merge-event", group, indexed);
}

fn check_event_wire_fixture(name: &str, group: InstructionGroup, mut indexed: ShieldedTransaction) {
    let origin = ring_event_origin_in(std::slice::from_ref(&group), 0, RING).unwrap();
    origin.bind_transaction(&mut indexed, RING).unwrap();
    let fixture = serde_json::json!({
        "ring": RING.to_string(),
        "source": {
            "programId": POOL.to_string(),
            "accounts": group.inner[0].accounts.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "dataHex": hex::encode(&group.inner[0].data),
        },
        "eventDataHex": hex::encode(&group.inner[1].data),
        "expected": {
            "viewingKeyHex": hex::encode(origin.event.event.tx_viewing_pk),
            "saltHex": hex::encode(origin.event.event.salt),
            "nullifiersHex": indexed.nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
            "messages": indexed.messages.iter().map(|message| serde_json::json!({"viewTagHex": hex::encode(message.view_tag), "dataHex": hex::encode(&message.data)})).collect::<Vec<_>>(),
            "outputs": indexed.output_slots.iter().map(|slot| serde_json::json!({
                "viewTagHex": hex::encode(slot.view_tag), "hashHex": hex::encode(slot.output_context.hash),
                "payloadHex": hex::encode(&slot.payload), "treeId": slot.output_context.tree_id, "leafIndex": slot.output_context.leaf_index,
            })).collect::<Vec<_>>(),
        },
    });
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("WRITE_RING_EVENT_FIXTURE").is_some() {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
        )
        .unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture, pinned);
}

fn confirmed_deposit_fixture() -> (InstructionGroup, ShieldedTransaction) {
    use zolana_event::{
        encode_encrypted_ring_deposit_output, encode_event_instruction, EncryptedRingDepositData,
        EncryptedRingDepositOutput, EventKind, GeneralEvent, OutputUtxo, SplTransfer,
    };
    use zolana_interface::instruction::instruction_data::deposit::{
        DepositAssetKind, RingDepositEntry,
    };
    let (mut group, mut indexed) = confirmed_transfer_fixture();
    indexed.proofless = true;
    indexed.tx_viewing_pk = None;
    indexed.salt = None;
    indexed.nullifiers.clear();
    indexed.messages.clear();
    indexed.output_slots.truncate(1);
    let encrypted = EncryptedRingDepositData {
        tx_viewing_pk: *zolana_keypair::X25519Keypair::from_bytes(&[7; 32])
            .pubkey()
            .as_bytes(),
        salt: [8; 16],
        ciphertext: vec![99, 100],
    };
    let deposit = RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: [7; 32],
            owner_utxo_hash: [12; 32],
            amount: 123,
            ring_data_hash: [13; 32],
            encrypted: encrypted.clone(),
        }],
    };
    indexed.output_slots[0].payload =
        encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
            owner_utxo_hash: [12; 32],
            asset: SOL_MINT.to_bytes(),
            amount: 123,
            data_hash: None,
            ring_program_id: RING.to_bytes(),
            ring_data_hash: [13; 32],
            encrypted,
        });
    let event = GeneralEvent {
        inputs: Vec::new(),
        outputs: vec![OutputUtxo {
            view_tag: [7; 32],
            utxo_hash: [6; 32],
            data: indexed.output_slots[0].payload.clone(),
        }],
        messages: Vec::new(),
        tx_viewing_pk: [0; 33],
        salt: [0; 16],
        first_output_leaf_index: 42,
        output_tree: zolana_interface::pda::tree(3).to_bytes(),
        spl_transfers: vec![SplTransfer {
            is_deposit: true,
            amount: 123,
            asset: None,
        }],
    };
    group.inner[0].data = [vec![tag::RING_DEPOSIT], deposit.serialize().unwrap()].concat();
    group.inner[1].data = encode_event_instruction(EventKind::Deposit, &event);
    (group, indexed)
}

fn confirmed_merge_fixture() -> (InstructionGroup, ShieldedTransaction) {
    use zolana_event::{encode_event_instruction, EventKind, InputTreeSequence, MergeEvent};
    use zolana_interface::instruction::instruction_data::{
        merge_ring::MergeRingIxData,
        merge_transact::{MergeOutputEncryption, MergeProof, MergeTransactIxData},
    };
    let (mut group, mut indexed) = confirmed_transfer_fixture();
    indexed.tx_viewing_pk = None;
    indexed.salt = None;
    indexed.messages.clear();
    indexed.output_slots.truncate(1);
    indexed.output_slots[0].view_tag = [20; 32];
    indexed.output_slots[0].payload =
        zolana_event::encode_merge_output_data(zolana_event::MergeOutputDataRef {
            salt: &[7; 16],
            ciphertext: &[[0; 32]; 3],
            ring_data_hash: Some(&[13; 32]),
        });
    let data = MergeRingIxData {
        output_ring_data_hash: [13; 32],
        member_registry_root: [14; 32],
        merge: MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [6; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [7; 16],
                ciphertext: [[0; 32]; 3],
            },
            private_tx_hash: [0; 32],
            nullifiers: indexed.nullifiers.clone(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    };
    let event = MergeEvent {
        input_trees: vec![InputTreeSequence {
            tree: zolana_interface::pda::tree(1).to_bytes(),
            first_input_queue_seq: 5,
        }],
        output_tree: zolana_interface::pda::tree(3).to_bytes(),
        output_leaf_index: 42,
        output_view_tag: [20; 32],
    };
    group.inner[0].data = [vec![tag::RING_MERGE_TRANSACT], data.serialize().unwrap()].concat();
    group.inner[1].data = encode_event_instruction(EventKind::Merge, &event);
    (group, indexed)
}

#[test]
fn rpc_origin_binds_the_confirmed_slot() {
    let origin =
        confirmed_origin(withdrawing_transaction(Vec::new(), Vec::new()), 0, RING).unwrap();
    let mut indexed = ShieldedTransaction {
        slot: 7,
        tx_signature: Signature::from([6; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: Vec::new(),
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    origin.bind_transaction(&mut indexed, RING).unwrap();
    indexed.slot = 8;
    assert!(matches!(
        origin.bind_transaction(&mut indexed, RING),
        Err(AuditError::ConfirmedEventMismatch)
    ));
}
