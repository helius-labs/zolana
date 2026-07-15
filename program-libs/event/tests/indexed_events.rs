//! Indexed-event discovery for every SPP instruction that emits a `GeneralEvent`.

use solana_pubkey::Pubkey;
use zolana_event::{
    decode_event_instruction, encode_event_instruction, event_kind_from_indexed,
    indexed_events_from_instruction_groups, instruction_may_emit_events, tag, EventKind,
    GeneralEvent, IndexedEvent, InstructionGroup, ParsedInstruction,
};

#[test]
fn event_kind_comes_from_payload_not_instruction_tag() {
    let emit_data = encode_event_instruction(EventKind::Transact, sample_general_event());
    let indexed = IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: emit_data.get(1..).unwrap_or_default().to_vec(),
        decoded: decode_event_instruction(&emit_data),
    };
    assert_eq!(indexed.tag, tag::EMIT_EVENT);
    assert_eq!(event_kind_from_indexed(&indexed), Some(EventKind::Transact));
    assert_ne!(indexed.tag, EventKind::Transact as u8);
}

fn sample_general_event() -> GeneralEvent {
    GeneralEvent {
        inputs: Vec::new(),
        outputs: Vec::new(),
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: 0,
        output_tree: [0u8; 32],
        relay_fee: None,
        deposit_withdraw: None,
    }
}

fn emit_event_data(kind: EventKind) -> Vec<u8> {
    encode_event_instruction(kind, sample_general_event())
}

#[test]
fn direct_transact_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(spp, Vec::new(), vec![tag::TRANSACT], Some(1)),
        inner: vec![ParsedInstruction::new(
            spp,
            Vec::new(),
            emit_event_data(EventKind::Transact),
            Some(2),
        )],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
    assert!(events[0].decoded.is_ok());
}

#[test]
fn zone_transact_cpi_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let zone = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(zone, vec![spp], vec![tag::ZONE_TRANSACT], Some(1)),
        inner: vec![
            ParsedInstruction::new(spp, Vec::new(), vec![tag::ZONE_TRANSACT], Some(2)),
            ParsedInstruction::new(
                spp,
                Vec::new(),
                emit_event_data(EventKind::Transact),
                Some(3),
            ),
        ],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
}

#[test]
fn zone_authority_transact_cpi_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let zone = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(zone, vec![spp], vec![tag::ZONE_AUTHORITY_TRANSACT], Some(1)),
        inner: vec![
            ParsedInstruction::new(spp, Vec::new(), vec![tag::ZONE_AUTHORITY_TRANSACT], Some(2)),
            ParsedInstruction::new(
                spp,
                Vec::new(),
                emit_event_data(EventKind::Transact),
                Some(3),
            ),
        ],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
}

#[test]
fn merge_and_zone_merge_emit_events_are_indexed() {
    let spp = Pubkey::new_unique();

    for (source_tag, kind) in [
        (tag::MERGE_TRANSACT, EventKind::Merge),
        (tag::ZONE_MERGE_TRANSACT, EventKind::Merge),
    ] {
        let group = InstructionGroup {
            outer: ParsedInstruction::new(spp, Vec::new(), vec![source_tag], Some(1)),
            inner: vec![ParsedInstruction::new(
                spp,
                Vec::new(),
                emit_event_data(kind),
                Some(2),
            )],
        };
        let events = indexed_events_from_instruction_groups(spp, &[group]);
        assert_eq!(events.len(), 1, "source tag {source_tag}");
    }
}

#[test]
fn unrelated_emit_event_without_event_source_parent_is_ignored() {
    let spp = Pubkey::new_unique();
    let other = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(other, Vec::new(), vec![tag::CREATE_TREE], Some(1)),
        inner: vec![ParsedInstruction::new(
            spp,
            Vec::new(),
            emit_event_data(EventKind::Transact),
            Some(2),
        )],
    };

    assert!(indexed_events_from_instruction_groups(spp, &[group]).is_empty());
}

#[test]
fn instruction_may_emit_events_matches_direct_and_zone_wrappers() {
    let spp = Pubkey::new_unique();
    let zone = Pubkey::new_unique();

    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(spp, Vec::new(), vec![tag::TRANSACT], None),
    ));
    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(spp, Vec::new(), vec![tag::MERGE_TRANSACT], None),
    ));

    for zone_tag in [
        tag::ZONE_DEPOSIT,
        tag::ZONE_TRANSACT,
        tag::ZONE_AUTHORITY_TRANSACT,
        tag::ZONE_MERGE_TRANSACT,
    ] {
        assert!(
            instruction_may_emit_events(
                spp,
                &ParsedInstruction::new(zone, vec![spp], vec![zone_tag], None),
            ),
            "zone wrapper tag {zone_tag}"
        );
    }

    assert!(!instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(zone, Vec::new(), vec![tag::ZONE_TRANSACT], None),
    ));
    assert!(!instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(zone, vec![spp], vec![tag::TRANSACT], None),
    ));
}
