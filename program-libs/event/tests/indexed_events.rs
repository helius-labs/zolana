//! Indexed-event discovery for every state-changing SPP event source.

use solana_pubkey::Pubkey;
use zolana_event::{
    encode_deposit_event, encode_merge_event, encode_transact_event, event_kind_from_indexed,
    indexed_events_from_instruction_groups, instruction_may_emit_events,
    reconstruction::{general_event_from_site, ReconstructError},
    EventKind, GeneralEvent, IndexedEvent, InstructionGroup, MergeEvent, ParsedInstruction,
    SplTransfer, TransactEvent,
};
use zolana_interface::instruction::tag;
#[cfg(feature = "nullifier-tree")]
use zolana_tree::NullifierTreeUpdateEvent;

#[test]
fn event_kind_comes_from_payload_not_instruction_tag() {
    let emit_data = transact_emit_event_data();
    let indexed = IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: emit_data.get(1..).unwrap_or_default().to_vec(),
        source_instruction_tag: tag::TRANSACT,
        decoded: Err(ReconstructError::InvalidParentInstruction),
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
        spl_transfers: Vec::new(),
    }
}

fn transact_emit_event_data() -> Vec<u8> {
    encode_transact_event(&TransactEvent {
        first_input_queue_seq: 7,
        first_output_leaf_index: 11,
    })
    .to_vec()
}

fn merge_emit_event_data() -> Vec<u8> {
    encode_merge_event(&MergeEvent {
        first_input_queue_seq: 7,
        first_output_leaf_index: 11,
        output_view_tag: [13; 32],
    })
    .to_vec()
}

#[test]
fn spl_transfer_round_trip_preserves_full_u64_amounts_and_asset_order() {
    let mut event = sample_general_event();
    event.spl_transfers = vec![
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
    ];

    let encoded = encode_deposit_event(&event);
    let decoded = general_event_from_site(
        tag::DEPOSIT,
        &[tag::DEPOSIT],
        &[],
        encoded.get(1..).expect("event instruction tag"),
    )
    .expect("decode event");

    assert_eq!(decoded, event);
}

#[test]
fn direct_transact_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(spp, Vec::new(), vec![tag::TRANSACT], Some(1)),
        inner: vec![ParsedInstruction::new(
            spp,
            Vec::new(),
            transact_emit_event_data(),
            Some(2),
        )],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
    assert_eq!(
        event_kind_from_indexed(&events[0]),
        Some(EventKind::Transact)
    );
}

#[test]
fn ring_transact_cpi_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let ring = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(ring, vec![spp], vec![tag::RING_TRANSACT], Some(1)),
        inner: vec![
            ParsedInstruction::new(spp, Vec::new(), vec![tag::RING_TRANSACT], Some(2)),
            ParsedInstruction::new(spp, Vec::new(), transact_emit_event_data(), Some(3)),
        ],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
}

#[test]
fn ring_authority_transact_cpi_emit_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let ring = Pubkey::new_unique();
    let group = InstructionGroup {
        outer: ParsedInstruction::new(ring, vec![spp], vec![tag::RING_AUTHORITY_TRANSACT], Some(1)),
        inner: vec![
            ParsedInstruction::new(spp, Vec::new(), vec![tag::RING_AUTHORITY_TRANSACT], Some(2)),
            ParsedInstruction::new(spp, Vec::new(), transact_emit_event_data(), Some(3)),
        ],
    };

    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
}

#[test]
fn merge_and_ring_merge_emit_events_are_indexed() {
    let spp = Pubkey::new_unique();

    for source_tag in [tag::MERGE_TRANSACT, tag::RING_MERGE_TRANSACT] {
        let group = InstructionGroup {
            outer: ParsedInstruction::new(spp, Vec::new(), vec![source_tag], Some(1)),
            inner: vec![ParsedInstruction::new(
                spp,
                Vec::new(),
                merge_emit_event_data(),
                Some(2),
            )],
        };
        let events = indexed_events_from_instruction_groups(spp, &[group]);
        assert_eq!(events.len(), 1, "source tag {source_tag}");
    }
}

#[cfg(feature = "nullifier-tree")]
#[test]
fn nullifier_tree_update_event_is_indexed() {
    let spp = Pubkey::new_unique();
    let update = NullifierTreeUpdateEvent {
        merkle_tree_pubkey: [1; 32],
        zkp_batch_size: 250,
        old_next_index: 500,
        start_sequence_number: 3,
        first_root_index: 4,
        num_update: 2,
        first_zkp_batch_index: 1,
        new_root: [2; 32],
    };
    let group = InstructionGroup {
        outer: ParsedInstruction::new(
            spp,
            Vec::new(),
            vec![tag::BATCH_UPDATE_NULLIFIER_TREE],
            Some(1),
        ),
        inner: vec![ParsedInstruction::new(
            spp,
            Vec::new(),
            zolana_event::encode_nullifier_tree_update_event(&update),
            Some(2),
        )],
    };

    assert!(instruction_may_emit_events(spp, &group.outer));
    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
    let event = events.first().expect("one nullifier-tree event");
    assert_eq!(
        event.source_instruction_tag,
        tag::BATCH_UPDATE_NULLIFIER_TREE
    );
    assert_eq!(
        event_kind_from_indexed(event),
        Some(EventKind::NullifierTreeUpdate)
    );
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
            transact_emit_event_data(),
            Some(2),
        )],
    };

    assert!(indexed_events_from_instruction_groups(spp, &[group]).is_empty());
}

#[test]
fn instruction_may_emit_events_matches_direct_and_ring_wrappers() {
    let spp = Pubkey::new_unique();
    let ring = Pubkey::new_unique();

    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(spp, Vec::new(), vec![tag::TRANSACT], None),
    ));
    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(spp, Vec::new(), vec![tag::MERGE_TRANSACT], None),
    ));
    assert!(instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(
            spp,
            Vec::new(),
            vec![tag::BATCH_UPDATE_NULLIFIER_TREE],
            None,
        ),
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
                &ParsedInstruction::new(ring, vec![spp], vec![ring_tag], None),
            ),
            "ring wrapper tag {ring_tag}"
        );
    }

    assert!(!instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(ring, Vec::new(), vec![tag::RING_TRANSACT], None),
    ));
    assert!(!instruction_may_emit_events(
        spp,
        &ParsedInstruction::new(ring, vec![spp], vec![tag::TRANSACT], None),
    ));
}
