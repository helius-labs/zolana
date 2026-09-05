use solana_signature::Signature;
use zolana_event::{encode_transact_event, GeneralEvent, Input, TransactEvent};
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

#[test]
fn indexed_emit_event_round_trip_through_index_events() {
    use solana_pubkey::Pubkey;
    use zolana_event::{
        indexed_events_from_instruction_groups, InstructionGroup, ParsedInstruction,
    };
    use zolana_interface::{
        instruction::{
            tag, CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof,
        },
        N_PUBLIC_SLOTS,
    };
    use zolana_program_test::index_events;

    let spp = Pubkey::new_unique();
    let event = sample_transact_event();
    let first_input = event.inputs.first().expect("sample has an input");
    let parent = TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: event.tx_viewing_pk,
        salt: event.salt,
        interface_transfers: Vec::new(),
        outputs: event
            .outputs
            .iter()
            .map(|output| TransactOutput {
                utxo_hash: output.utxo_hash,
                owner_tag: OwnerTag::Inline(output.view_tag),
                data: Some(output.data.clone()),
            })
            .collect(),
        messages: event.messages.clone(),
        data_hash: None,
        ring_data_hash: None,
        circuit: CircuitId::ConfidentialEddsa(
            event.inputs.len() as u8,
            event.outputs.len() as u8,
            N_PUBLIC_SLOTS as u8,
        ),
        proof: TransactProof::zeroed(),
        private_tx_hash: [0u8; 32],
        inputs: event
            .inputs
            .iter()
            .map(|input| InputUtxo {
                nullifier_hash: input.nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect(),
    };
    let mut parent_data = vec![tag::TRANSACT];
    parent_data.extend_from_slice(&parent.serialize().expect("serialize parent transact"));
    let emit_data = encode_transact_event(&TransactEvent {
        first_input_queue_seq: first_input.input_queue_seq,
        first_output_leaf_index: event.first_output_leaf_index,
    })
    .to_vec();
    // Real transact parents have the five fixed accounts followed by one
    // nullifier PDA per input. Reconstruction intentionally uses the same
    // layout as the program rather than accepting a shortened test fixture.
    let mut parent_accounts = vec![
        Pubkey::new_unique(),
        Pubkey::new_from_array(first_input.tree),
        Pubkey::new_from_array(event.output_tree),
        spp,
        Pubkey::new_unique(),
    ];
    parent_accounts.extend(event.inputs.iter().map(|_| Pubkey::new_unique()));
    let group = InstructionGroup {
        outer: ParsedInstruction::new(spp, parent_accounts, parent_data, Some(1)),
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
