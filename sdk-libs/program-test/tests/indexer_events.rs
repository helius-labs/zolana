use solana_signature::Signature;
use zolana_event::{EventKind, GeneralEvent, Input};
use zolana_program_test::TestIndexer;

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
        messages: Vec::new(),
        outputs: vec![
            zolana_event::OutputUtxo {
                view_tag: [0x11; 32],
                utxo_hash: {
                    let mut h = [0u8; 32];
                    h[31] = 1;
                    h
                },
                data: vec![1, 2, 3],
            },
            zolana_event::OutputUtxo {
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
        spl_transfers: Vec::new(),
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

/// The `transact` instruction data behind [`sample_transact_event`]: the indexer
/// rebuilds outputs, nullifier, viewing key and salt from it, so only the
/// execution-assigned values travel in the emitted [`TransactEvent`].
fn sample_transact_instruction_data() -> Vec<u8> {
    use zolana_interface::instruction::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof,
    };

    let event = sample_transact_event();
    let ix = TransactIxData {
        expiry_unix_ts: 0,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 0),
        tx_viewing_pk: event.tx_viewing_pk,
        salt: event.salt,
        proof: TransactProof::zeroed(),
        inputs: event
            .inputs
            .iter()
            .map(|input| InputUtxo {
                nullifier_hash: input.nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: event
            .outputs
            .iter()
            .map(|output| TransactOutput {
                utxo_hash: output.utxo_hash,
                owner_tag: OwnerTag::Inline(output.view_tag),
                data: Some(output.data.clone()),
            })
            .collect(),
        messages: Vec::new(),
    };
    let mut data = vec![zolana_event::tag::TRANSACT];
    data.extend_from_slice(&ix.serialize().expect("serialize transact"));
    data
}

#[test]
fn indexed_emit_event_round_trip_through_index_events() {
    use solana_pubkey::Pubkey;
    use zolana_event::{encode_event_instruction, InputTreeSequence, TransactEvent};
    use zolana_event_parser::{
        indexed_events_from_instruction_groups, InstructionGroup, ParsedInstruction,
    };
    use zolana_program_test::index_events;

    let spp = Pubkey::new_unique();
    let expected = sample_transact_event();
    let emit_data = encode_event_instruction(
        EventKind::Transact,
        &TransactEvent {
            input_trees: vec![InputTreeSequence {
                tree: [1u8; 32],
                first_input_queue_seq: 0,
            }],
            output_tree: expected.output_tree,
            first_output_leaf_index: expected.first_output_leaf_index,
            spl_transfers: Vec::new(),
        },
    );
    let group = InstructionGroup {
        outer: ParsedInstruction::new(spp, Vec::new(), sample_transact_instruction_data(), Some(1)),
        inner: vec![ParsedInstruction::new(spp, Vec::new(), emit_data, Some(2))],
    };
    let events = indexed_events_from_instruction_groups(spp, &[group]);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events.first().map(|event| event.decoded.clone()),
        Some(Ok(expected))
    );

    let mut indexer = TestIndexer::new();
    let signature = Signature::from([0xAB; 64]);
    index_events(&mut indexer, &events, signature).expect("index transact event");
    assert_eq!(indexer.utxos().len(), 2);
    assert!(indexer.fetch_transaction_by_signature(&signature).is_some());
}
