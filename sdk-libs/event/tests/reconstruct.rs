//! `GeneralEvent` reconstruction from a minimal event plus its source instruction.

mod support;

use solana_pubkey::Pubkey;
use support::{
    emit_event_data, emit_instruction, input_trees, input_trees_in_order, merge_event, merge_ix,
    merge_ring_ix, source, transact_ix, transact_source, INPUT_TREE, OUTPUT_TREE, SALT,
    TX_VIEWING_PK,
};
use zolana_event::{
    tag, EventKind, GeneralEvent, Input, InputTreeSequence, MessageData, NullifierTreeUpdateEvent,
    OutputUtxo, SplTransfer, TransactEvent,
};
use zolana_event_parser::{
    indexed_events_from_instruction_groups, reconstruct_general_event, EventDecodeError,
    InstructionGroup, ParsedInstruction,
};
use zolana_interface::instruction::{InputUtxo, InterfaceTransfer, OwnerTag, TransactOutput};

const OWNER_ACCOUNT_INDEX: u8 = 6;
/// The second declared input tree of a multi-tree spend.
const SECOND_INPUT_TREE: [u8; 32] = [3u8; 32];

fn input(nullifier_byte: u8) -> InputUtxo {
    input_in_tree(nullifier_byte, 0)
}

fn input_in_tree(nullifier_byte: u8, tree_index: u8) -> InputUtxo {
    InputUtxo {
        nullifier_hash: [nullifier_byte; 32],
        tree_index,
    }
}

fn accounts_with_owner(owner: Pubkey) -> Vec<Pubkey> {
    let mut accounts: Vec<Pubkey> = (0..OWNER_ACCOUNT_INDEX)
        .map(|_| Pubkey::new_unique())
        .collect();
    accounts.push(owner);
    accounts
}

fn transfer_event() -> TransactEvent {
    TransactEvent {
        input_trees: input_trees(10),
        output_tree: OUTPUT_TREE,
        first_output_leaf_index: 5,
    }
}

fn transfer_ix() -> zolana_interface::instruction::TransactIxData {
    transact_ix(
        vec![input(0xA0), input(0xA1)],
        vec![
            TransactOutput {
                utxo_hash: [0xB0; 32],
                owner_tag: OwnerTag::Inline([0x11; 32]),
                data: Some(vec![1, 2, 3]),
            },
            TransactOutput {
                utxo_hash: [0xB1; 32],
                owner_tag: OwnerTag::Account(OWNER_ACCOUNT_INDEX),
                data: None,
            },
            TransactOutput {
                utxo_hash: [0xB2; 32],
                owner_tag: OwnerTag::Inline([0x33; 32]),
                data: Some(vec![4, 5, 6]),
            },
        ],
        vec![MessageData {
            view_tag: [9; 32],
            data: vec![7, 8],
        }],
        vec![InterfaceTransfer::SolWithdrawal { amount: 40 }],
    )
}

fn expected_transfer(owner: Pubkey) -> GeneralEvent {
    GeneralEvent {
        inputs: vec![
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 10,
                nullifier: [0xA0; 32],
            },
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 11,
                nullifier: [0xA1; 32],
            },
        ],
        outputs: vec![
            OutputUtxo {
                view_tag: [0x11; 32],
                utxo_hash: [0xB0; 32],
                data: vec![1, 2, 3],
            },
            OutputUtxo {
                view_tag: owner.to_bytes(),
                utxo_hash: [0xB1; 32],
                data: Vec::new(),
            },
            OutputUtxo {
                view_tag: [0x33; 32],
                utxo_hash: [0xB2; 32],
                data: vec![4, 5, 6],
            },
        ],
        messages: vec![MessageData {
            view_tag: [9; 32],
            data: vec![7, 8],
        }],
        tx_viewing_pk: TX_VIEWING_PK,
        salt: SALT,
        first_output_leaf_index: 5,
        output_tree: OUTPUT_TREE,
        spl_transfers: vec![SplTransfer {
            is_deposit: false,
            amount: 40,
            asset: None,
        }],
    }
}

#[test]
fn transact_event_rebuilds_outputs_messages_and_sequences_from_instruction_data() {
    let spp = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let src = transact_source(
        spp,
        tag::TRANSACT,
        accounts_with_owner(owner),
        &transfer_ix(),
        1,
    );

    let event = reconstruct_general_event(
        &src,
        &emit_event_data(EventKind::Transact, &transfer_event()),
    )
    .expect("reconstruct transact");

    assert_eq!(event, expected_transfer(owner));
}

#[test]
fn ring_transact_cpi_resolves_owner_accounts_against_the_spp_inner_instruction() {
    let spp = Pubkey::new_unique();
    let ring = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    // The ring program's own account list must not be consulted.
    let ring_accounts = (0..=OWNER_ACCOUNT_INDEX)
        .map(|_| Pubkey::new_unique())
        .collect();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(ring, ring_accounts, vec![tag::RING_TRANSACT], 1),
        inner: vec![
            transact_source(
                spp,
                tag::RING_TRANSACT,
                accounts_with_owner(owner),
                &transfer_ix(),
                2,
            ),
            emit_instruction(spp, EventKind::Transact, &transfer_event(), 3),
        ],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events.first().and_then(|event| event.decoded.as_ref().ok()),
        Some(&expected_transfer(owner))
    );
}

#[test]
fn owner_account_index_past_the_account_list_is_an_error() {
    let spp = Pubkey::new_unique();
    let src = transact_source(
        spp,
        tag::TRANSACT,
        vec![Pubkey::new_unique(); usize::from(OWNER_ACCOUNT_INDEX)],
        &transfer_ix(),
        1,
    );

    assert_eq!(
        reconstruct_general_event(
            &src,
            &emit_event_data(EventKind::Transact, &transfer_event())
        ),
        Err(EventDecodeError::OutputOwnerAccountMissing(
            OWNER_ACCOUNT_INDEX
        ))
    );
}

#[test]
fn transact_body_under_a_merge_instruction_is_rejected() {
    let spp = Pubkey::new_unique();
    let src = source(
        spp,
        tag::MERGE_TRANSACT,
        Vec::new(),
        merge_ix([0xC0; 32]).serialize().expect("serialize merge"),
        1,
    );

    assert_eq!(
        reconstruct_general_event(
            &src,
            &emit_event_data(EventKind::Transact, &transfer_event())
        ),
        Err(EventDecodeError::UnsupportedSourceInstruction(
            tag::MERGE_TRANSACT
        ))
    );
}

#[test]
fn malformed_source_instruction_data_is_an_error() {
    let spp = Pubkey::new_unique();
    let src = source(spp, tag::TRANSACT, Vec::new(), vec![1, 2, 3], 1);

    assert_eq!(
        reconstruct_general_event(
            &src,
            &emit_event_data(EventKind::Transact, &transfer_event())
        ),
        Err(EventDecodeError::InvalidSourceInstructionData)
    );
}

/// Settlement groups are the last accounts of the instruction, in leg order:
/// SPL deposit `[mint, spl_interface, token_authority, user_token_account,
/// token_program]`, SPL withdrawal `[cpi_authority, mint, spl_interface,
/// user_token_account, token_program]`, SOL `[sol_interface, recipient]`.
#[test]
fn spl_legs_take_their_mint_from_the_settlement_group() {
    let spp = Pubkey::new_unique();
    let deposit_mint = Pubkey::new_unique();
    let withdrawal_mint = Pubkey::new_unique();
    let mut accounts: Vec<Pubkey> = (0..4).map(|_| Pubkey::new_unique()).collect();
    accounts.push(deposit_mint);
    accounts.extend((0..4).map(|_| Pubkey::new_unique()));
    accounts.push(Pubkey::new_unique());
    accounts.push(withdrawal_mint);
    accounts.extend((0..3).map(|_| Pubkey::new_unique()));
    accounts.extend((0..2).map(|_| Pubkey::new_unique()));
    let ix = transact_ix(
        vec![input(0xA0)],
        Vec::new(),
        Vec::new(),
        vec![
            InterfaceTransfer::SplDeposit {
                amount: 1,
                spl_interface_bump: 0,
            },
            InterfaceTransfer::SplWithdrawal {
                amount: 2,
                spl_interface_bump: 0,
            },
            InterfaceTransfer::SolDeposit { amount: 3 },
        ],
    );
    let src = transact_source(spp, tag::TRANSACT, accounts, &ix, 1);

    let event = reconstruct_general_event(
        &src,
        &emit_event_data(EventKind::Transact, &transfer_event()),
    )
    .expect("reconstruct transact");

    assert_eq!(
        event.spl_transfers,
        vec![
            SplTransfer {
                is_deposit: true,
                amount: 1,
                asset: Some(deposit_mint.to_bytes()),
            },
            SplTransfer {
                is_deposit: false,
                amount: 2,
                asset: Some(withdrawal_mint.to_bytes()),
            },
            SplTransfer {
                is_deposit: true,
                amount: 3,
                asset: None,
            },
        ]
    );
}

#[test]
fn account_list_shorter_than_the_settlement_groups_is_an_error() {
    let spp = Pubkey::new_unique();
    // `transfer_ix` has one SOL withdrawal leg, which needs two accounts.
    let src = transact_source(
        spp,
        tag::TRANSACT,
        vec![Pubkey::new_unique()],
        &transfer_ix(),
        1,
    );

    assert_eq!(
        reconstruct_general_event(
            &src,
            &emit_event_data(EventKind::Transact, &transfer_event())
        ),
        Err(EventDecodeError::MissingSettlementAccount)
    );
}

/// A transact with no outputs, messages or settlement legs, so the assertion is
/// about the input assignment alone.
fn reconstruct_inputs(
    inputs: Vec<InputUtxo>,
    input_trees: Vec<InputTreeSequence>,
) -> Result<GeneralEvent, EventDecodeError> {
    let spp = Pubkey::new_unique();
    let ix = transact_ix(inputs, Vec::new(), Vec::new(), Vec::new());
    let src = transact_source(spp, tag::TRANSACT, Vec::new(), &ix, 1);
    let mut event = transfer_event();
    event.input_trees = input_trees;

    reconstruct_general_event(&src, &emit_event_data(EventKind::Transact, &event))
}

fn expected_input_only_event(inputs: Vec<Input>) -> GeneralEvent {
    GeneralEvent {
        inputs,
        outputs: Vec::new(),
        messages: Vec::new(),
        tx_viewing_pk: TX_VIEWING_PK,
        salt: SALT,
        first_output_leaf_index: 5,
        output_tree: OUTPUT_TREE,
        spl_transfers: Vec::new(),
    }
}

#[test]
fn inputs_take_the_tree_and_sequence_of_the_entry_their_index_names() {
    assert_eq!(
        reconstruct_inputs(
            vec![
                input_in_tree(0xA0, 0),
                input_in_tree(0xA1, 0),
                input_in_tree(0xA2, 1),
            ],
            input_trees_in_order([(INPUT_TREE, 10), (SECOND_INPUT_TREE, 70)]),
        ),
        Ok(expected_input_only_event(vec![
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 10,
                nullifier: [0xA0; 32],
            },
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 11,
                nullifier: [0xA1; 32],
            },
            Input {
                tree: SECOND_INPUT_TREE,
                input_queue_seq: 70,
                nullifier: [0xA2; 32],
            },
        ]))
    );
}

/// The program groups inputs by tree, so each tree owns a contiguous run, but
/// the reconstruction must not lean on it: an interleaved head followed by a
/// grouped tail still numbers every tree from its own first sequence.
#[test]
fn input_sequences_count_per_tree_when_the_indexes_interleave() {
    assert_eq!(
        reconstruct_inputs(
            vec![
                input_in_tree(0xA0, 0),
                input_in_tree(0xA1, 1),
                input_in_tree(0xA2, 0),
                input_in_tree(0xA3, 1),
                input_in_tree(0xA4, 1),
            ],
            input_trees_in_order([(INPUT_TREE, 10), (SECOND_INPUT_TREE, 70)]),
        ),
        Ok(expected_input_only_event(vec![
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 10,
                nullifier: [0xA0; 32],
            },
            Input {
                tree: SECOND_INPUT_TREE,
                input_queue_seq: 70,
                nullifier: [0xA1; 32],
            },
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 11,
                nullifier: [0xA2; 32],
            },
            Input {
                tree: SECOND_INPUT_TREE,
                input_queue_seq: 71,
                nullifier: [0xA3; 32],
            },
            Input {
                tree: SECOND_INPUT_TREE,
                input_queue_seq: 72,
                nullifier: [0xA4; 32],
            },
        ]))
    );
}

#[test]
fn an_input_tree_index_with_no_emitted_entry_is_an_error() {
    assert_eq!(
        reconstruct_inputs(vec![input_in_tree(0xA0, 1)], input_trees(10)),
        Err(EventDecodeError::InputTreeIndexOutOfRange(1))
    );
}

#[test]
fn a_transact_event_naming_no_input_tree_is_an_error() {
    assert_eq!(
        reconstruct_inputs(vec![input(0xA0)], Vec::new()),
        Err(EventDecodeError::UnsupportedInputTreeCount(0))
    );
}

#[test]
fn queue_sequence_overflow_is_an_error() {
    let spp = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let src = transact_source(
        spp,
        tag::TRANSACT,
        accounts_with_owner(owner),
        &transfer_ix(),
        1,
    );
    let mut event = transfer_event();
    event.input_trees = vec![InputTreeSequence {
        tree: INPUT_TREE,
        first_input_queue_seq: u64::MAX,
    }];

    assert_eq!(
        reconstruct_general_event(&src, &emit_event_data(EventKind::Transact, &event)),
        Err(EventDecodeError::IndexOverflow)
    );
}

#[test]
fn merge_with_more_than_one_input_tree_is_not_reconstructible_yet() {
    let spp = Pubkey::new_unique();
    let src = source(
        spp,
        tag::MERGE_TRANSACT,
        Vec::new(),
        merge_ix([0xC0; 32]).serialize().expect("serialize merge"),
        1,
    );
    let mut event = merge_event([0xD0; 32]);
    event.input_trees.clear();

    assert_eq!(
        reconstruct_general_event(&src, &emit_event_data(EventKind::Merge, &event)),
        Err(EventDecodeError::UnsupportedInputTreeCount(0))
    );
}

fn expected_merge(output_view_tag: [u8; 32], output_data: Vec<u8>) -> GeneralEvent {
    GeneralEvent {
        inputs: (0..8u64)
            .map(|i| Input {
                tree: INPUT_TREE,
                input_queue_seq: 20 + i,
                nullifier: [0x40 + u8::try_from(i).expect("shape"); 32],
            })
            .collect(),
        outputs: vec![OutputUtxo {
            view_tag: output_view_tag,
            utxo_hash: [0xC0; 32],
            data: output_data,
        }],
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: 9,
        output_tree: OUTPUT_TREE,
        spl_transfers: Vec::new(),
    }
}

#[test]
fn merge_transact_event_rebuilds_eight_inputs_and_the_owner_indexed_output() {
    let spp = Pubkey::new_unique();
    let src = source(
        spp,
        tag::MERGE_TRANSACT,
        Vec::new(),
        merge_ix([0xC0; 32]).serialize().expect("serialize merge"),
        1,
    );

    let event = reconstruct_general_event(
        &src,
        &emit_event_data(EventKind::Merge, &merge_event([0xD0; 32])),
    )
    .expect("reconstruct merge");

    assert_eq!(event, expected_merge([0xD0; 32], Vec::new()));
}

#[test]
fn merge_ring_event_republishes_the_output_ring_data_hash() {
    let spp = Pubkey::new_unique();
    let src = source(
        spp,
        tag::RING_MERGE_TRANSACT,
        Vec::new(),
        merge_ring_ix([0xC0; 32], [0xE0; 32])
            .serialize()
            .expect("serialize merge ring"),
        1,
    );

    let event = reconstruct_general_event(
        &src,
        &emit_event_data(EventKind::Merge, &merge_event([0x40; 32])),
    )
    .expect("reconstruct merge ring");

    assert_eq!(event, expected_merge([0x40; 32], vec![0xE0; 32]));
}

#[test]
fn merge_body_under_a_transact_instruction_is_rejected() {
    let spp = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let src = transact_source(
        spp,
        tag::TRANSACT,
        accounts_with_owner(owner),
        &transfer_ix(),
        1,
    );

    assert_eq!(
        reconstruct_general_event(
            &src,
            &emit_event_data(EventKind::Merge, &merge_event([0xD0; 32]))
        ),
        Err(EventDecodeError::UnsupportedSourceInstruction(
            tag::TRANSACT
        ))
    );
}

#[test]
fn deposit_event_still_decodes_from_its_full_body() {
    let spp = Pubkey::new_unique();
    let src = source(spp, tag::DEPOSIT, Vec::new(), Vec::new(), 1);
    let deposit = GeneralEvent {
        inputs: Vec::new(),
        outputs: vec![OutputUtxo {
            view_tag: [1; 32],
            utxo_hash: [2; 32],
            data: vec![3],
        }],
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: 4,
        output_tree: OUTPUT_TREE,
        spl_transfers: vec![
            SplTransfer {
                is_deposit: true,
                amount: u64::MAX,
                asset: Some([0xA5; 32]),
            },
            SplTransfer {
                is_deposit: true,
                amount: 7,
                asset: None,
            },
        ],
    };

    assert_eq!(
        reconstruct_general_event(&src, &emit_event_data(EventKind::Deposit, &deposit)),
        Ok(deposit)
    );
}

#[test]
fn nullifier_tree_update_has_no_general_event_view() {
    let spp = Pubkey::new_unique();
    let src = source(
        spp,
        tag::BATCH_UPDATE_NULLIFIER_TREE,
        Vec::new(),
        Vec::new(),
        1,
    );
    let update = NullifierTreeUpdateEvent {
        merkle_tree_pubkey: INPUT_TREE,
        zkp_batch_size: 10,
        old_next_index: 0,
        start_sequence_number: 0,
        first_root_index: 0,
        num_update: 1,
        first_zkp_batch_index: 0,
        new_root: [0; 32],
    };

    assert_eq!(
        reconstruct_general_event(
            &src,
            &emit_event_data(EventKind::NullifierTreeUpdate, &update)
        ),
        Err(EventDecodeError::NotAGeneralEvent)
    );
}

#[test]
fn emit_event_data_must_start_with_the_emit_event_tag() {
    let spp = Pubkey::new_unique();
    let src = source(spp, tag::TRANSACT, Vec::new(), Vec::new(), 1);
    let mut data = emit_event_data(EventKind::Transact, &transfer_event());
    if let Some(first) = data.first_mut() {
        *first = tag::TRANSACT;
    }

    assert_eq!(
        reconstruct_general_event(&src, &data),
        Err(EventDecodeError::InvalidInstructionTag(tag::TRANSACT))
    );
    assert_eq!(
        reconstruct_general_event(&src, &[]),
        Err(EventDecodeError::MissingInstructionTag)
    );
    assert_eq!(
        reconstruct_general_event(&src, &[tag::EMIT_EVENT, 200]),
        Err(EventDecodeError::InvalidEventKind(200))
    );
}
