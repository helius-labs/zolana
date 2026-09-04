//! Reconstruction must reproduce what the program used to log.
//!
//! The event body shrank to the execution-assigned positions, so every other
//! field an indexer reads now comes from the parent instruction. If that
//! derivation drifts from the instruction encoding the event stream is silently
//! wrong, which is why this pins the mapping directly.

use zolana_event::{
    reconstruction::{
        general_event_from_site, reconstruct_merge_event, reconstruct_transact_event,
        ReconstructError,
    },
    EventKind, GeneralEvent, Input, MergeEvent, OutputUtxo, SplTransfer, TransactEvent,
};
use zolana_interface::instruction::instruction_data::{
    merge_ring::MergeRingIxData,
    merge_transact::{MergeProof, MergeTransactIxData, MERGE_DEFAULT_INPUT_COUNT},
    transact::CircuitId,
};
use zolana_interface::instruction::{
    tag, InputUtxo, InterfaceTransfer, MessageData, OwnerTag, TransactIxData, TransactOutput,
    TransactProof,
};

const PAYER: [u8; 32] = [1; 32];
const INPUT_TREE: [u8; 32] = [2; 32];
const OUTPUT_TREE: [u8; 32] = [3; 32];
const SPP: [u8; 32] = [4; 32];
const SYSTEM: [u8; 32] = [5; 32];
const OWNER: [u8; 32] = [6; 32];
const RING_CONFIG: [u8; 32] = [7; 32];
const SOL_INTERFACE: [u8; 32] = [8; 32];
const SOL_USER: [u8; 32] = [9; 32];
const MERGE_INPUT_TREE: [u8; 32] = [31; 32];
const MERGE_OUTPUT_TREE: [u8; 32] = [32; 32];
const RING_DATA_HASH: [u8; 32] = [33; 32];

fn accounts() -> Vec<[u8; 32]> {
    transact_accounts(tag::TRANSACT, 2, &[OWNER], &[SOL_INTERFACE, SOL_USER])
}

fn transact_accounts(
    source_tag: u8,
    input_count: usize,
    owner_signers: &[[u8; 32]],
    settlements: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    let mut accounts = vec![PAYER, INPUT_TREE, OUTPUT_TREE, SPP, SYSTEM];
    if source_tag != tag::TRANSACT {
        accounts.push(RING_CONFIG);
    }
    accounts.extend((0..input_count).map(|index| [70 + index as u8; 32]));
    accounts.extend_from_slice(owner_signers);
    accounts.extend_from_slice(settlements);
    accounts
}

fn merge_accounts(input_count: usize) -> Vec<[u8; 32]> {
    let mut accounts = vec![
        MERGE_INPUT_TREE,
        MERGE_OUTPUT_TREE,
        [80; 32],
        [81; 32],
        [82; 32],
        [83; 32],
    ];
    accounts.extend((0..input_count).map(|index| [90 + index as u8; 32]));
    accounts
}

fn ix_data() -> TransactIxData {
    TransactIxData {
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
                // Index 7 is the owner signer after the two nullifier PDAs.
                owner_tag: OwnerTag::Account(7),
                data: None,
            },
        ],
        messages: vec![MessageData {
            view_tag: [15; 32],
            data: vec![16, 17, 18],
        }],
        data_hash: None,
        ring_data_hash: None,
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
    }
}

fn parent_data(data: &TransactIxData) -> Vec<u8> {
    let mut bytes = vec![tag::TRANSACT];
    bytes.extend_from_slice(&data.serialize().unwrap());
    bytes
}

fn merge_ix_data() -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: 99,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [34; 32],
        eddsa_owner: false,
        private_tx_hash: [35; 32],
        nullifiers: (0..MERGE_DEFAULT_INPUT_COUNT)
            .map(|offset| {
                let byte = u8::try_from(offset).expect("supported merge shape fits in u8");
                [byte; 32]
            })
            .collect(),
        utxo_tree_root_index: vec![1; MERGE_DEFAULT_INPUT_COUNT],
        nullifier_tree_root_index: vec![2; MERGE_DEFAULT_INPUT_COUNT],
    }
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
fn every_transact_source_uses_the_same_flat_instruction_decoder() {
    let mut data = ix_data();
    data.interface_transfers.clear();
    data.outputs
        .get_mut(1)
        .expect("fixture has an account-tagged output")
        .owner_tag = OwnerTag::Inline(OWNER);
    let event = TransactEvent {
        first_input_queue_seq: 41,
        first_output_leaf_index: 100,
    };

    for source_tag in [
        tag::TRANSACT,
        tag::RING_TRANSACT,
        tag::RING_AUTHORITY_TRANSACT,
    ] {
        data.circuit = match source_tag {
            tag::TRANSACT => CircuitId::ConfidentialEddsa(2, 2, 3),
            tag::RING_TRANSACT => CircuitId::RingEddsa(2, 2, 3),
            tag::RING_AUTHORITY_TRANSACT => CircuitId::RingAuthority(2, 2, 3),
            _ => unreachable!(),
        };
        let mut parent = vec![source_tag];
        parent.extend_from_slice(&data.serialize().expect("serialize transact"));
        let parent_accounts = transact_accounts(source_tag, data.inputs.len(), &[], &[]);
        let rebuilt = reconstruct_transact_event(source_tag, &parent, &parent_accounts, &event)
            .expect("reconstruct transact source");

        assert_eq!(rebuilt.inputs.len(), data.inputs.len(), "tag {source_tag}");
        assert_eq!(
            rebuilt.outputs.len(),
            data.outputs.len(),
            "tag {source_tag}"
        );
        assert_eq!(rebuilt.output_tree, OUTPUT_TREE, "tag {source_tag}");
    }
}

#[test]
fn settlement_reconstruction_handles_every_layout_after_owner_signers() {
    const SOL_DEPOSITOR: [u8; 32] = [40; 32];
    const SOL_RECIPIENT: [u8; 32] = [41; 32];
    const DEPOSIT_MINT: [u8; 32] = [42; 32];
    const WITHDRAWAL_MINT: [u8; 32] = [43; 32];

    let cases = [
        (
            InterfaceTransfer::SolDeposit { amount: 1 },
            vec![[50; 32], SOL_DEPOSITOR],
            SplTransfer {
                is_deposit: true,
                amount: 1,
                asset: None,
            },
        ),
        (
            InterfaceTransfer::SplDeposit {
                amount: 2,
                spl_interface_bump: 51,
            },
            vec![DEPOSIT_MINT, [52; 32], [53; 32], [54; 32], [55; 32]],
            SplTransfer {
                is_deposit: true,
                amount: 2,
                asset: Some(DEPOSIT_MINT),
            },
        ),
        (
            InterfaceTransfer::SolWithdrawal { amount: 3 },
            vec![[56; 32], SOL_RECIPIENT],
            SplTransfer {
                is_deposit: false,
                amount: 3,
                asset: None,
            },
        ),
        (
            InterfaceTransfer::SplWithdrawal {
                amount: 4,
                spl_interface_bump: 57,
            },
            vec![[58; 32], WITHDRAWAL_MINT, [59; 32], [60; 32], [61; 32]],
            SplTransfer {
                is_deposit: false,
                amount: 4,
                asset: Some(WITHDRAWAL_MINT),
            },
        ),
    ];

    let mut data = ix_data();
    data.interface_transfers = cases.iter().map(|(transfer, _, _)| *transfer).collect();
    for output in &mut data.outputs {
        output.owner_tag = OwnerTag::Inline([62; 32]);
    }

    // Real transact layout before settlement: fixed five-account prefix, one
    // nullifier PDA per input, then an arbitrary run of owner signers. The
    // reconstructor intentionally finds settlement from the account-list tail.
    let mut parent_accounts = vec![
        PAYER,
        INPUT_TREE,
        OUTPUT_TREE,
        SPP,
        SYSTEM,
        [63; 32],
        [64; 32],
        [65; 32],
        [66; 32],
    ];
    for (_, settlement_accounts, _) in &cases {
        parent_accounts.extend_from_slice(settlement_accounts);
    }

    let rebuilt = reconstruct_transact_event(
        tag::TRANSACT,
        &parent_data(&data),
        &parent_accounts,
        &TransactEvent {
            first_input_queue_seq: 0,
            first_output_leaf_index: 0,
        },
    )
    .expect("reconstruct every settlement layout");
    let expected: Vec<_> = cases.into_iter().map(|(_, _, transfer)| transfer).collect();

    assert_eq!(rebuilt.spl_transfers, expected);
}

#[test]
fn ring_merge_reconstruction_uses_the_embedded_merge_payload() {
    let instruction = MergeRingIxData {
        output_ring_data_hash: RING_DATA_HASH,
        merge: merge_ix_data(),
    };
    let mut parent_data = vec![tag::RING_MERGE_TRANSACT];
    parent_data.extend_from_slice(&instruction.serialize().expect("serialize ring merge"));
    let event = MergeEvent {
        first_input_queue_seq: 50,
        first_output_leaf_index: 100,
        // Ring merge derives this from its first nullifier instead.
        output_view_tag: [255; 32],
    };

    let rebuilt = reconstruct_merge_event(
        tag::RING_MERGE_TRANSACT,
        &parent_data,
        &merge_accounts(instruction.merge.nullifiers.len()),
        &event,
    )
    .expect("reconstruct ring merge");
    let inputs = instruction
        .merge
        .nullifiers
        .iter()
        .enumerate()
        .map(|(offset, nullifier)| Input {
            tree: MERGE_INPUT_TREE,
            input_queue_seq: 50_u64
                .checked_add(u64::try_from(offset).expect("merge input count fits in u64"))
                .expect("test queue sequence does not overflow"),
            nullifier: *nullifier,
        })
        .collect();
    let output_view_tag = *instruction
        .merge
        .nullifiers
        .first()
        .expect("supported merge shape has an input");

    assert_eq!(
        rebuilt,
        GeneralEvent {
            inputs,
            outputs: vec![OutputUtxo {
                view_tag: output_view_tag,
                utxo_hash: instruction.merge.output_utxo_hash,
                data: RING_DATA_HASH.to_vec(),
            }],
            messages: Vec::new(),
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            first_output_leaf_index: 100,
            output_tree: MERGE_OUTPUT_TREE,
            spl_transfers: Vec::new(),
        }
    );
}

#[test]
fn direct_merge_reconstruction_retains_the_event_view_tag() {
    let instruction = merge_ix_data();
    let mut parent_data = vec![tag::MERGE_TRANSACT];
    parent_data.extend_from_slice(&instruction.serialize().expect("serialize direct merge"));
    let event = MergeEvent {
        first_input_queue_seq: 50,
        first_output_leaf_index: 100,
        output_view_tag: [44; 32],
    };

    let rebuilt = reconstruct_merge_event(
        tag::MERGE_TRANSACT,
        &parent_data,
        &merge_accounts(instruction.nullifiers.len()),
        &event,
    )
    .expect("reconstruct direct merge");

    assert_eq!(rebuilt.inputs.len(), MERGE_DEFAULT_INPUT_COUNT);
    assert_eq!(
        rebuilt
            .inputs
            .first()
            .expect("merge has inputs")
            .input_queue_seq,
        50
    );
    assert_eq!(
        rebuilt
            .inputs
            .last()
            .expect("merge has inputs")
            .input_queue_seq,
        57
    );
    assert_eq!(rebuilt.outputs.len(), 1);
    let output = rebuilt.outputs.first().expect("merge has one output");
    assert_eq!(output.view_tag, event.output_view_tag);
    assert_eq!(output.utxo_hash, instruction.output_utxo_hash);
    assert!(output.data.is_empty());
    assert_eq!(rebuilt.output_tree, MERGE_OUTPUT_TREE);
}

#[test]
fn an_owner_tag_past_the_account_list_is_rejected() {
    let mut data = ix_data();
    data.outputs[1].owner_tag = OwnerTag::Account(200);
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
        Err(ReconstructError::InvalidAccountCount),
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
        Err(ReconstructError::InvalidParentInstruction),
    );
}

#[test]
fn source_tag_must_match_the_parent_instruction() {
    let data = ix_data();
    let mut parent = parent_data(&data);
    parent[0] = tag::RING_TRANSACT;
    let event = TransactEvent {
        first_input_queue_seq: 0,
        first_output_leaf_index: 0,
    };

    assert_eq!(
        reconstruct_transact_event(tag::TRANSACT, &parent, &accounts(), &event),
        Err(ReconstructError::InvalidParentInstruction),
    );
}

#[test]
fn transact_reconstruction_rejects_a_non_transact_source_without_settlements() {
    let mut data = ix_data();
    data.interface_transfers.clear();
    let mut parent = vec![tag::DEPOSIT];
    parent.extend_from_slice(&data.serialize().unwrap());
    let event = TransactEvent {
        first_input_queue_seq: 0,
        first_output_leaf_index: 0,
    };

    assert_eq!(
        reconstruct_transact_event(tag::DEPOSIT, &parent, &accounts(), &event),
        Err(ReconstructError::UnsupportedSourceInstruction(tag::DEPOSIT)),
    );
}

#[test]
fn event_kind_must_match_the_source_instruction() {
    assert_eq!(
        general_event_from_site(
            tag::TRANSACT,
            &[tag::TRANSACT],
            &accounts(),
            &[EventKind::Deposit as u8],
        ),
        Err(ReconstructError::MismatchedEventKind {
            source_instruction_tag: tag::TRANSACT,
            event_kind: EventKind::Deposit as u8,
        }),
    );
}
