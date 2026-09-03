//! Reconstruction must reproduce what the program used to log.
//!
//! The event body shrank to the execution-assigned positions, so every other
//! field an indexer reads now comes from the parent instruction. If that
//! derivation drifts from the instruction encoding the event stream is silently
//! wrong, which is why this pins the mapping directly.

use zolana_event::TransactEvent;
use zolana_interface::event_reconstruction::{reconstruct_transact_event, ReconstructError};
use zolana_interface::instruction::instruction_data::transact::CircuitId;
use zolana_interface::instruction::{
    tag, InputUtxo, InterfaceTransfer, MessageData, OwnerTag, TransactIxBound, TransactIxData,
    TransactIxTail, TransactOutput, TransactProof,
};

const PAYER: [u8; 32] = [1; 32];
const INPUT_TREE: [u8; 32] = [2; 32];
const OUTPUT_TREE: [u8; 32] = [3; 32];
const SPP: [u8; 32] = [4; 32];
const SYSTEM: [u8; 32] = [5; 32];
const OWNER: [u8; 32] = [6; 32];

fn accounts() -> Vec<[u8; 32]> {
    vec![PAYER, INPUT_TREE, OUTPUT_TREE, SPP, SYSTEM, OWNER]
}

fn ix_data() -> TransactIxData {
    TransactIxData {
        bound: TransactIxBound {
            expiry_unix_ts: 99,
            tx_viewing_pk: [7; 33],
            salt: [8; 16],
            interface_transfers: vec![InterfaceTransfer::SolWithdrawal { amount: 5 }],
            outputs: vec![
                TransactOutput {
                    utxo_hash: [10; 32],
                    owner_tag: OwnerTag::Inline([11; 32]),
                    data: Some(vec![12, 13]),
                },
                TransactOutput {
                    utxo_hash: [14; 32],
                    // Index 5 is the owner account appended after the fixed prefix.
                    owner_tag: OwnerTag::Account(5),
                    data: None,
                },
            ],
            messages: vec![MessageData {
                view_tag: [15; 32],
                data: vec![16, 17, 18],
            }],
        },
        tail: TransactIxTail {
            circuit: CircuitId::ConfidentialEddsa(2, 2, 3),
            proof: TransactProof {
                a: [19; 32],
                b: [20; 64],
                c: [21; 32],
            },
            private_tx_hash: [22; 32],
            inputs: vec![
                InputUtxo {
                    nullifier_hash: [23; 32],
                    nullifier_tree_root_index: 1,
                    utxo_tree_root_index: 2,
                },
                InputUtxo {
                    nullifier_hash: [24; 32],
                    nullifier_tree_root_index: 3,
                    utxo_tree_root_index: 4,
                },
            ],
            data_hash: None,
            ring_data_hash: None,
        },
    }
}

fn parent_data(data: &TransactIxData) -> Vec<u8> {
    let mut bytes = vec![tag::TRANSACT];
    bytes.extend_from_slice(&data.serialize().unwrap());
    bytes
}

#[test]
fn transact_reconstruction_matches_the_instruction_it_came_from() {
    let data = ix_data();
    let event = TransactEvent {
        first_input_queue_seq: 41,
        first_output_leaf_index: 100,
    };
    let rebuilt =
        reconstruct_transact_event(tag::TRANSACT, &parent_data(&data), &accounts(), &event)
            .expect("reconstruct");

    // Queue sequences and leaf indices run contiguously from the single pair the
    // event carries.
    assert_eq!(rebuilt.inputs.len(), 2);
    assert_eq!(rebuilt.inputs[0].input_queue_seq, 41);
    assert_eq!(rebuilt.inputs[1].input_queue_seq, 42);
    assert_eq!(rebuilt.first_output_leaf_index, 100);

    // Trees come from the parent account list, not the event.
    assert!(rebuilt.inputs.iter().all(|input| input.tree == INPUT_TREE));
    assert_eq!(rebuilt.output_tree, OUTPUT_TREE);

    // Nullifiers, ciphertexts, messages and the decryption context are the
    // instruction's own bytes.
    assert_eq!(rebuilt.inputs[0].nullifier, [23; 32]);
    assert_eq!(rebuilt.inputs[1].nullifier, [24; 32]);
    assert_eq!(rebuilt.outputs[0].utxo_hash, [10; 32]);
    assert_eq!(rebuilt.outputs[0].data, vec![12, 13]);
    assert_eq!(rebuilt.outputs[1].data, Vec::<u8>::new());
    assert_eq!(rebuilt.messages.len(), 1);
    assert_eq!(rebuilt.messages[0].data, vec![16, 17, 18]);
    assert_eq!(rebuilt.tx_viewing_pk, [7; 33]);
    assert_eq!(rebuilt.salt, [8; 16]);

    // An inline tag resolves to itself; an account tag resolves through the
    // parent account list, exactly as the program's OWNER public input does.
    assert_eq!(rebuilt.outputs[0].view_tag, [11; 32]);
    assert_eq!(rebuilt.outputs[1].view_tag, OWNER);
}

#[test]
fn an_owner_tag_past_the_account_list_is_rejected() {
    let mut data = ix_data();
    data.bound.outputs[1].owner_tag = OwnerTag::Account(200);
    let event = TransactEvent {
        first_input_queue_seq: 0,
        first_output_leaf_index: 0,
    };
    assert_eq!(
        reconstruct_transact_event(tag::TRANSACT, &parent_data(&data), &accounts(), &event),
        Err(ReconstructError::OwnerTagAccountMissing),
    );
}

#[test]
fn a_truncated_account_list_is_rejected_rather_than_silently_indexed() {
    let data = ix_data();
    let event = TransactEvent {
        first_input_queue_seq: 0,
        first_output_leaf_index: 0,
    };
    assert_eq!(
        reconstruct_transact_event(tag::TRANSACT, &parent_data(&data), &[PAYER], &event),
        Err(ReconstructError::MissingAccount),
    );
}

#[test]
fn a_parent_that_does_not_parse_is_rejected() {
    let event = TransactEvent {
        first_input_queue_seq: 0,
        first_output_leaf_index: 0,
    };
    assert_eq!(
        reconstruct_transact_event(
            tag::TRANSACT,
            &[tag::TRANSACT, 0, 1, 2],
            &accounts(),
            &event
        ),
        Err(ReconstructError::UnparsableParent),
    );
}
