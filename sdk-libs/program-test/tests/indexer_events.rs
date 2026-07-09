use rings_event::{encode_event_instruction, EventKind, GeneralEvent, Input};
use rings_program_test::TestIndexer;
use solana_signature::Signature;

fn sample_transact_event() -> GeneralEvent {
    GeneralEvent {
        inputs: vec![Input {
            tree: [1u8; 32],
            input_queue_seq: 0,
            nullifier: {
                let mut n = [0u8; 32];
                n[31] = 0xAA;
                n
            },
        }],
        outputs: vec![
            rings_event::OutputUtxo {
                view_tag: [0x11; 32],
                utxo_hash: {
                    let mut h = [0u8; 32];
                    h[31] = 1;
                    h
                },
                data: vec![1, 2, 3],
            },
            rings_event::OutputUtxo {
                view_tag: [0x33; 32],
                utxo_hash: {
                    let mut h = [0u8; 32];
                    h[31] = 2;
                    h
                },
                data: vec![4, 5, 6],
            },
        ],
        tx_viewing_pk: [0u8; 33],
        salt: [0x55; 16],
        first_output_leaf_index: 0,
        output_tree: [0x66; 32],
        relay_fee: None,
        deposit_withdraw: None,
    }
}

#[test]
fn test_indexer_replays_transact_event_outputs_and_nullifiers() {
    let mut indexer = TestIndexer::new();
    let event = sample_transact_event();
    let signature = Signature::from([0xAB; 64]);

    indexer
        .record_state_change(&event)
        .expect("record transact event");
    indexer.record_transaction(signature, &event, false);

    assert_eq!(indexer.utxos().len(), 2);
    assert_eq!(indexer.utxos()[0].leaf_index, 0);
    assert_eq!(indexer.utxos()[1].leaf_index, 1);
    let mut spent = [0u8; 32];
    spent[31] = 0xAA;
    assert!(indexer.is_nullifier_spent(&spent));
    assert_eq!(indexer.fetch_by_view_tag(&[0x11; 32]).count(), 1);
    assert_eq!(indexer.fetch_by_view_tag(&[0x33; 32]).count(), 1);
    assert!(indexer.fetch_transaction_by_signature(&signature).is_some());
    let tx = indexer.fetch_transaction_by_signature(&signature).unwrap();
    assert_eq!(tx.output_slots.len(), 2);
    assert_eq!(tx.nullifiers, vec![spent]);
    assert!(!tx.proofless);
}

#[test]
fn test_indexer_transact_leaf_indices_must_be_contiguous() {
    let mut indexer = TestIndexer::new();
    let mut event = sample_transact_event();
    event.first_output_leaf_index = 1;
    assert!(indexer.record_state_change(&event).is_err());
}

#[test]
fn indexed_emit_event_round_trip_through_index_events() {
    use rings_event::{
        indexed_events_from_instruction_groups, tag, InstructionGroup, ParsedInstruction,
    };
    use rings_program_test::index_events;
    use solana_pubkey::Pubkey;

    let spp = Pubkey::new_unique();
    let emit_data = encode_event_instruction(EventKind::Transact, sample_transact_event());
    let group = InstructionGroup {
        outer: ParsedInstruction::new(spp, Vec::new(), vec![tag::TRANSACT], Some(1)),
        inner: vec![ParsedInstruction::new(spp, Vec::new(), emit_data, Some(2))],
    };
    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);

    let mut indexer = TestIndexer::new();
    let signature = Signature::from([0xAB; 64]);
    index_events(&mut indexer, &events, signature).expect("index transact event");
    assert_eq!(indexer.utxos().len(), 2);
    assert!(indexer.fetch_transaction_by_signature(&signature).is_some());
}
