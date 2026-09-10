//! Nullifier-tree batch updates are read from the emitted event, never from
//! the instruction that requested them.

use photon_indexer::ingester::{
    parser::nullifier_tree_batch_update_parser::{
        has_nullifier_tree_batch_update, parse_nullifier_tree_batch_updates,
    },
    typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo},
};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_interface::event::{encode_nullifier_tree_update_event, EventKind};
use zolana_interface::{instruction::tag, pda};
use zolana_tree::NullifierTreeUpdateEvent;

fn tree() -> Pubkey {
    Pubkey::new_from_array([7; 32])
}

fn event(num_update: u32) -> NullifierTreeUpdateEvent {
    NullifierTreeUpdateEvent {
        merkle_tree_pubkey: tree().to_bytes(),
        zkp_batch_size: 250,
        old_next_index: 500,
        start_sequence_number: 3,
        first_root_index: 4,
        num_update,
        first_zkp_batch_index: 2,
        new_root: [9; 32],
    }
}

fn instruction(program_id: Pubkey, data: Vec<u8>, stack_height: u32) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![],
        data,
        stack_height: Some(stack_height),
    }
}

fn batch_update_instruction() -> Instruction {
    instruction(
        pda::shielded_pool_program_id(),
        vec![tag::BATCH_UPDATE_NULLIFIER_TREE, 1, 2, 3],
        1,
    )
}

fn tx_with(outer: Instruction, inner: Vec<Instruction>) -> TransactionInfo {
    TransactionInfo {
        instruction_groups: vec![InstructionGroup {
            outer_instruction: outer,
            inner_instructions: inner,
        }],
        signature: Signature::from([8; 64]),
        error: None,
    }
}

fn tx_emitting(event: &NullifierTreeUpdateEvent) -> TransactionInfo {
    let emit = instruction(
        pda::shielded_pool_program_id(),
        encode_nullifier_tree_update_event(event),
        2,
    );
    tx_with(batch_update_instruction(), vec![emit])
}

#[test]
fn parses_single_batch_event() {
    let tx = tx_emitting(&event(1));

    let state_update = parse_nullifier_tree_batch_updates(&tx).unwrap().unwrap();

    assert_eq!(state_update.nullifier_tree_batch_updates.len(), 1);
    let update = state_update
        .nullifier_tree_batch_updates
        .first()
        .expect("one update");
    assert_eq!(update.tree, tree());
    assert_eq!(update.new_root, [9; 32]);
    assert_eq!(update.zkp_batch_size, 250);
    assert_eq!(update.num_update, 1);
    assert_eq!(update.appended_count(), 250);
    assert_eq!(update.signature, tx.signature);
    assert!(has_nullifier_tree_batch_update(&tx));
}

/// The instruction that triggers a cascade looks no different; only the event
/// says three batches landed under it.
#[test]
fn parses_cascade_of_three_batches() {
    let tx = tx_emitting(&event(3));

    let state_update = parse_nullifier_tree_batch_updates(&tx).unwrap().unwrap();

    let update = state_update
        .nullifier_tree_batch_updates
        .first()
        .expect("one update");
    assert_eq!(update.num_update, 3);
    assert_eq!(update.appended_count(), 750);
}

/// The tree's sequence number advances once per applied zkp batch, and the root
/// index a client quotes is derived from it. Taking `start_sequence_number`
/// alone would leave photon short by one per extra batch, pointing clients at
/// the wrong slot of the root history.
#[test]
fn cascade_sequence_number_counts_batches_not_events() {
    let single = tx_emitting(&event(1));
    let cascade = tx_emitting(&event(3));

    let seq = |tx: &TransactionInfo| {
        parse_nullifier_tree_batch_updates(tx)
            .unwrap()
            .unwrap()
            .nullifier_tree_batch_updates
            .first()
            .expect("one update")
            .sequence_number
    };

    assert_eq!(seq(&single), 3);
    assert_eq!(seq(&cascade), 5);
}

/// A proof cached out of order applies nothing and emits nothing. Reading the
/// instruction instead would record a root the tree never took.
#[test]
fn ignores_instruction_that_emitted_no_event() {
    let tx = tx_with(batch_update_instruction(), vec![]);

    assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
    assert!(has_nullifier_tree_batch_update(&tx));
}

#[test]
fn ignores_general_event_under_a_transact() {
    let tx = tx_with(
        instruction(pda::shielded_pool_program_id(), vec![tag::TRANSACT], 1),
        vec![instruction(
            pda::shielded_pool_program_id(),
            vec![tag::EMIT_EVENT, EventKind::Transact as u8],
            2,
        )],
    );

    assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
    assert!(!has_nullifier_tree_batch_update(&tx));
}

#[test]
fn ignores_event_forged_by_a_foreign_parent() {
    let mut tx = tx_emitting(&event(1));
    let group = tx.instruction_groups.first_mut().expect("one group");
    group.outer_instruction.program_id = Pubkey::new_from_array([9; 32]);

    assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
}

#[test]
fn ignores_failed_transactions() {
    let mut tx = tx_emitting(&event(1));
    tx.error = Some("failed".to_string());

    assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
    assert!(!has_nullifier_tree_batch_update(&tx));
}
