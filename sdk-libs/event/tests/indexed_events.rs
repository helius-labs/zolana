//! Indexed-event discovery for every SPP instruction that emits an event: the
//! `EMIT_EVENT` self-CPI counts only when its direct parent is an SPP event
//! source, and the parent is what the event is rebuilt against.

mod support;

use solana_pubkey::Pubkey;
use support::{
    emit_event_data, emit_instruction, input_trees, merge_event, merge_ix, merge_ring_ix, source,
    transact_ix, transact_source, OUTPUT_TREE,
};
use zolana_event::{tag, EventKind, TransactEvent};
use zolana_event_parser::{
    event_kind_from_indexed, indexed_events_from_instruction_groups, instruction_may_emit_events,
    reconstruct_general_event, IndexedEvent, InstructionGroup, ParsedInstruction,
};
use zolana_interface::instruction::{InputUtxo, OwnerTag, TransactIxData, TransactOutput};

fn one_in_one_out() -> TransactIxData {
    transact_ix(
        vec![InputUtxo {
            nullifier_hash: [0xA0; 32],
        }],
        vec![TransactOutput {
            utxo_hash: [0xB0; 32],
            owner_tag: OwnerTag::Inline([0x11; 32]),
            data: None,
        }],
        Vec::new(),
        Vec::new(),
    )
}

fn transact_event() -> TransactEvent {
    TransactEvent {
        input_trees: input_trees(0),
        output_tree: OUTPUT_TREE,
        first_output_leaf_index: 0,
    }
}

#[test]
fn event_kind_comes_from_payload_not_instruction_tag() {
    let spp = Pubkey::new_unique();
    let src = transact_source(spp, tag::TRANSACT, Vec::new(), &one_in_one_out(), 1);
    let emit_data = emit_event_data(EventKind::Transact, &transact_event());
    let indexed = IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: emit_data.get(1..).unwrap_or_default().to_vec(),
        decoded: reconstruct_general_event(&src, &emit_data),
    };
    assert_eq!(indexed.tag, tag::EMIT_EVENT);
    assert_eq!(event_kind_from_indexed(&indexed), Some(EventKind::Transact));
    assert_ne!(indexed.tag, EventKind::Transact as u8);
    assert!(indexed.decoded.is_ok());
}

#[test]
fn direct_transact_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: transact_source(spp, tag::TRANSACT, Vec::new(), &one_in_one_out(), 1),
        inner: vec![emit_instruction(
            spp,
            EventKind::Transact,
            &transact_event(),
            2,
        )],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
    assert!(events.iter().all(|event| event.decoded.is_ok()));
}

#[test]
fn ring_transact_cpi_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let ring = Pubkey::new_unique();
    for ring_tag in [tag::RING_TRANSACT, tag::RING_AUTHORITY_TRANSACT] {
        let group = InstructionGroup {
            outer: ParsedInstruction::new(ring, vec![spp], vec![ring_tag], 1),
            inner: vec![
                transact_source(spp, ring_tag, Vec::new(), &one_in_one_out(), 2),
                emit_instruction(spp, EventKind::Transact, &transact_event(), 3),
            ],
        };

        let events = indexed_events_from_instruction_groups(spp, &[group]);
        assert_eq!(events.len(), 1, "ring tag {ring_tag}");
        assert!(
            events.iter().all(|event| event.decoded.is_ok()),
            "ring tag {ring_tag}"
        );
    }
}

#[test]
fn merge_and_ring_merge_emit_events_are_indexed() {
    let spp = Pubkey::new_unique();
    let merge_bytes = merge_ix([0xC0; 32]).serialize().expect("serialize merge");
    let merge_ring_bytes = merge_ring_ix([0xC0; 32], [0xE0; 32])
        .serialize()
        .expect("serialize merge ring");

    for (source_tag, ix_bytes) in [
        (tag::MERGE_TRANSACT, merge_bytes),
        (tag::RING_MERGE_TRANSACT, merge_ring_bytes),
    ] {
        let group = InstructionGroup {
            outer: source(spp, source_tag, Vec::new(), ix_bytes, 1),
            inner: vec![emit_instruction(
                spp,
                EventKind::Merge,
                &merge_event([0xD0; 32]),
                2,
            )],
        };
        let events = indexed_events_from_instruction_groups(spp, &[group]);
        assert_eq!(events.len(), 1, "source tag {source_tag}");
        assert!(
            events.iter().all(|event| event.decoded.is_ok()),
            "source tag {source_tag}"
        );
    }
}

#[test]
fn unrelated_emit_event_without_event_source_parent_is_ignored() {
    let spp = Pubkey::new_unique();
    let other = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(other, Vec::new(), vec![tag::CREATE_TREE], 1),
        inner: vec![emit_instruction(
            spp,
            EventKind::Transact,
            &transact_event(),
            2,
        )],
    };

    assert!(indexed_events_from_instruction_groups(spp, &[group]).is_empty());
}

#[test]
fn emit_event_parented_by_another_emit_event_is_ignored() {
    let spp = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: transact_source(spp, tag::TRANSACT, Vec::new(), &one_in_one_out(), 1),
        inner: vec![
            emit_instruction(spp, EventKind::Transact, &transact_event(), 2),
            emit_instruction(spp, EventKind::Transact, &transact_event(), 3),
        ],
    };

    assert_eq!(
        indexed_events_from_instruction_groups(spp, &[group]).len(),
        1
    );
}

#[test]
fn instruction_may_emit_events_matches_direct_and_ring_wrappers() {
    let spp = Pubkey::new_unique();
    let ring = Pubkey::new_unique();

    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(spp, Vec::new(), vec![tag::TRANSACT], 1),
    ));
    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(spp, Vec::new(), vec![tag::MERGE_TRANSACT], 1),
    ));

    for ring_tag in [
        tag::RING_DEPOSIT,
        tag::RING_TRANSACT,
        tag::RING_AUTHORITY_TRANSACT,
        tag::RING_MERGE_TRANSACT,
    ] {
        assert!(
            instruction_may_emit_events(
                spp,
                &ParsedInstruction::new(ring, vec![spp], vec![ring_tag], 1),
            ),
            "ring wrapper tag {ring_tag}"
        );
    }

    assert!(!instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(ring, Vec::new(), vec![tag::RING_TRANSACT], 1),
    ));
    assert!(!instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(ring, vec![spp], vec![tag::TRANSACT], 1),
    ));
}
