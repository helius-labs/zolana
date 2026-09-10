//! Indexed-event discovery for every state-changing SPP event source.

mod support;

use solana_address::Address;
use support::{merge_fixture, transact_fixture, EventFixture};
use zolana_event::{
    event_kind_from_indexed, indexed_events_from_instruction_groups, instruction_may_emit_events,
    reconstruction::{general_event_from_site, ReconstructError},
    IndexedEvent, InstructionGroup, ParsedInstruction,
};
use zolana_interface::event::{
    encode_deposit_event, encode_transact_event, EventKind, GeneralEvent, Input, OutputUtxo,
    SplTransfer, TransactEvent,
};
use zolana_interface::instruction::instruction_data::merge_transact::MERGE_DEFAULT_INPUT_COUNT;
use zolana_interface::instruction::{tag, MessageData};
use zolana_tree::NullifierTreeUpdateEvent;

const INPUT_TREE: [u8; 32] = [21; 32];
const OUTPUT_TREE: [u8; 32] = [22; 32];

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

fn transact_event() -> GeneralEvent {
    GeneralEvent {
        inputs: vec![
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 7,
                nullifier: [31; 32],
            },
            Input {
                tree: INPUT_TREE,
                input_queue_seq: 8,
                nullifier: [32; 32],
            },
        ],
        outputs: vec![
            OutputUtxo {
                view_tag: [41; 32],
                utxo_hash: [51; 32],
                data: vec![1, 2, 3],
            },
            OutputUtxo {
                view_tag: [42; 32],
                utxo_hash: [52; 32],
                data: Vec::new(),
            },
            OutputUtxo {
                view_tag: [43; 32],
                utxo_hash: [53; 32],
                data: vec![4; 300],
            },
        ],
        messages: vec![MessageData {
            view_tag: [61; 32],
            data: vec![9, 9],
        }],
        tx_viewing_pk: [71; 33],
        salt: [72; 16],
        first_output_leaf_index: 11,
        output_tree: OUTPUT_TREE,
        spl_transfers: vec![
            SplTransfer {
                is_deposit: false,
                amount: 40,
                asset: Some([81; 32]),
            },
            SplTransfer {
                is_deposit: true,
                amount: 5,
                asset: None,
            },
        ],
    }
}

fn merge_event(source_instruction_tag: u8) -> GeneralEvent {
    let nullifiers: Vec<[u8; 32]> = (0..MERGE_DEFAULT_INPUT_COUNT)
        .map(|offset| {
            let byte = u8::try_from(offset).expect("merge input count fits in u8");
            [100 + byte; 32]
        })
        .collect();
    let first_nullifier = *nullifiers.first().expect("merge has inputs");
    let (view_tag, data) = if source_instruction_tag == tag::RING_MERGE_TRANSACT {
        (first_nullifier, vec![91; 32])
    } else {
        ([90; 32], Vec::new())
    };
    GeneralEvent {
        inputs: nullifiers
            .iter()
            .enumerate()
            .map(|(offset, nullifier)| Input {
                tree: INPUT_TREE,
                input_queue_seq: 7 + u64::try_from(offset).expect("offset fits in u64"),
                nullifier: *nullifier,
            })
            .collect(),
        outputs: vec![OutputUtxo {
            view_tag,
            utxo_hash: [92; 32],
            data,
        }],
        messages: Vec::new(),
        tx_viewing_pk: [0; 33],
        salt: [0; 16],
        first_output_leaf_index: 11,
        output_tree: OUTPUT_TREE,
        spl_transfers: Vec::new(),
    }
}

fn expected_indexed(
    fixture: &EventFixture,
    source_instruction_tag: u8,
    event: GeneralEvent,
) -> IndexedEvent {
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: fixture.payload(),
        source_instruction_tag,
        decoded: Ok(event),
    }
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
    let spp = Address::new_unique();
    let event = transact_event();
    let fixture = transact_fixture(spp, tag::TRANSACT, &event);
    let group = InstructionGroup {
        outer: ParsedInstruction::new(
            spp,
            fixture.parent_accounts.clone(),
            fixture.parent_data.clone(),
            Some(1),
        ),
        inner: vec![ParsedInstruction::new(
            spp,
            Vec::new(),
            fixture.emit_event_data.clone(),
            Some(2),
        )],
    };

    assert_eq!(
        indexed_events_from_instruction_groups(spp, &[group]),
        vec![expected_indexed(&fixture, tag::TRANSACT, event)]
    );
}

#[test]
fn ring_transact_cpi_emit_event_is_indexed() {
    let spp = Address::new_unique();
    let ring = Address::new_unique();
    let event = transact_event();
    let fixture = transact_fixture(spp, tag::RING_TRANSACT, &event);
    let group = InstructionGroup {
        outer: ParsedInstruction::new(ring, vec![spp], vec![tag::RING_TRANSACT], Some(1)),
        inner: vec![
            ParsedInstruction::new(
                spp,
                fixture.parent_accounts.clone(),
                fixture.parent_data.clone(),
                Some(2),
            ),
            ParsedInstruction::new(spp, Vec::new(), fixture.emit_event_data.clone(), Some(3)),
        ],
    };

    assert_eq!(
        indexed_events_from_instruction_groups(spp, &[group]),
        vec![expected_indexed(&fixture, tag::RING_TRANSACT, event)]
    );
}

#[test]
fn ring_authority_transact_cpi_emit_event_is_indexed() {
    let spp = Address::new_unique();
    let ring = Address::new_unique();
    let mut event = transact_event();
    event.outputs.truncate(2);
    event.spl_transfers.clear();
    let fixture = transact_fixture(spp, tag::RING_AUTHORITY_TRANSACT, &event);
    let group = InstructionGroup {
        outer: ParsedInstruction::new(ring, vec![spp], vec![tag::RING_AUTHORITY_TRANSACT], Some(1)),
        inner: vec![
            ParsedInstruction::new(
                spp,
                fixture.parent_accounts.clone(),
                fixture.parent_data.clone(),
                Some(2),
            ),
            ParsedInstruction::new(spp, Vec::new(), fixture.emit_event_data.clone(), Some(3)),
        ],
    };

    assert_eq!(
        indexed_events_from_instruction_groups(spp, &[group]),
        vec![expected_indexed(
            &fixture,
            tag::RING_AUTHORITY_TRANSACT,
            event
        )]
    );
}

#[test]
fn merge_and_ring_merge_emit_events_are_indexed() {
    let spp = Address::new_unique();

    for source_tag in [tag::MERGE_TRANSACT, tag::RING_MERGE_TRANSACT] {
        let event = merge_event(source_tag);
        let fixture = merge_fixture(source_tag, &event);
        let group = InstructionGroup {
            outer: ParsedInstruction::new(
                spp,
                fixture.parent_accounts.clone(),
                fixture.parent_data.clone(),
                Some(1),
            ),
            inner: vec![ParsedInstruction::new(
                spp,
                Vec::new(),
                fixture.emit_event_data.clone(),
                Some(2),
            )],
        };

        assert_eq!(
            indexed_events_from_instruction_groups(spp, &[group]),
            vec![expected_indexed(&fixture, source_tag, event)],
            "source tag {source_tag}"
        );
    }
}

#[test]
fn nullifier_tree_update_event_is_indexed() {
    let spp = Address::new_unique();
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
            zolana_interface::event::encode_nullifier_tree_update_event(&update),
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
    let spp = Address::new_unique();
    let other = Address::new_unique();
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
    let spp = Address::new_unique();
    let ring = Address::new_unique();

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
