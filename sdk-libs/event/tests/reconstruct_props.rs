//! Property tests for `GeneralEvent` reconstruction:
//!
//! 1. For any `transact` / `merge` instruction data and matching minimal event,
//!    the rebuilt `GeneralEvent` equals the view assembled directly from the
//!    generated values (outputs 1:1 under their resolved owner tag, contiguous
//!    queue sequence numbers, messages, viewing key and salt verbatim).
//! 2. Arbitrary source instructions and `EMIT_EVENT` bytes never panic.

mod support;

use proptest::prelude::*;
use solana_pubkey::Pubkey;
use support::{
    emit_event_data, emit_instruction, merge_ix, merge_ring_ix, source, transact_ix,
    transact_source, INPUT_TREE, OUTPUT_TREE, SALT, TX_VIEWING_PK,
};
use zolana_event::{
    tag, EventKind, GeneralEvent, Input, InputTreeSequence, MergeEvent, MessageData, OutputUtxo,
    SplTransfer, TransactEvent,
};
use zolana_event_parser::{
    indexed_events_from_instruction_groups, reconstruct_general_event, InstructionGroup,
    ParsedInstruction,
};
use zolana_interface::instruction::{
    instruction_data::merge_transact::MERGE_DEFAULT_INPUT_COUNT, InputUtxo, InterfaceTransfer,
    OwnerTag, TransactOutput,
};

/// Leaves room for `first_input_queue_seq + position` without overflow.
const MAX_FIRST_QUEUE_SEQ: u64 = u64::MAX - 16;

fn pubkey() -> impl Strategy<Value = Pubkey> {
    any::<[u8; 32]>().prop_map(Pubkey::new_from_array)
}

fn input_utxo() -> impl Strategy<Value = InputUtxo> {
    any::<[u8; 32]>().prop_map(|nullifier_hash| InputUtxo { nullifier_hash })
}

/// `OwnerTag::Account` indexes stay inside an account list of `account_count`.
fn transact_output(account_count: usize) -> impl Strategy<Value = TransactOutput> {
    let last_index = u8::try_from(account_count - 1).expect("test shape");
    (
        any::<[u8; 32]>(),
        prop_oneof![
            any::<[u8; 32]>().prop_map(OwnerTag::Inline),
            (0..=last_index).prop_map(OwnerTag::Account),
        ],
        // Beyond 255 bytes so the u16 data length prefix is exercised.
        prop::option::of(prop::collection::vec(any::<u8>(), 0..300)),
    )
        .prop_map(|(utxo_hash, owner_tag, data)| TransactOutput {
            utxo_hash,
            owner_tag,
            data,
        })
}

fn message_data() -> impl Strategy<Value = MessageData> {
    (
        any::<[u8; 32]>(),
        prop::collection::vec(any::<u8>(), 0..300),
    )
        .prop_map(|(view_tag, data)| MessageData { view_tag, data })
}

fn interface_transfer() -> impl Strategy<Value = InterfaceTransfer> {
    prop_oneof![
        any::<u64>().prop_map(|amount| InterfaceTransfer::SolDeposit { amount }),
        any::<u64>().prop_map(|amount| InterfaceTransfer::SolWithdrawal { amount }),
        (any::<u64>(), any::<u8>()).prop_map(|(amount, spl_interface_bump)| {
            InterfaceTransfer::SplDeposit {
                amount,
                spl_interface_bump,
            }
        }),
        (any::<u64>(), any::<u8>()).prop_map(|(amount, spl_interface_bump)| {
            InterfaceTransfer::SplWithdrawal {
                amount,
                spl_interface_bump,
            }
        }),
    ]
}

/// Settlement group layout, written out independently of the interface helpers
/// so a change to either side fails here.
fn settlement_group_size(transfer: &InterfaceTransfer) -> usize {
    match transfer {
        InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. } => 2,
        InterfaceTransfer::SplDeposit { .. } | InterfaceTransfer::SplWithdrawal { .. } => 5,
    }
}

fn mint_position(transfer: &InterfaceTransfer) -> Option<usize> {
    match transfer {
        InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. } => None,
        InterfaceTransfer::SplDeposit { .. } => Some(0),
        InterfaceTransfer::SplWithdrawal { .. } => Some(1),
    }
}

#[derive(Debug)]
struct TransactCase {
    /// Prefix accounts followed by one settlement group per interface transfer.
    accounts: Vec<Pubkey>,
    /// Number of accounts before the settlement groups; owner tags index these.
    prefix_len: usize,
    inputs: Vec<InputUtxo>,
    outputs: Vec<TransactOutput>,
    messages: Vec<MessageData>,
    interface_transfers: Vec<InterfaceTransfer>,
    first_input_queue_seq: u64,
    first_output_leaf_index: u64,
    source_tag: u8,
}

impl TransactCase {
    fn expected_spl_transfers(&self) -> Vec<SplTransfer> {
        let mut group_start = self.prefix_len;
        self.interface_transfers
            .iter()
            .map(|transfer| {
                let asset = mint_position(transfer).map(|position| {
                    self.accounts
                        .get(group_start + position)
                        .expect("strategy appends every settlement group")
                        .to_bytes()
                });
                group_start += settlement_group_size(transfer);
                SplTransfer {
                    is_deposit: transfer.is_deposit(),
                    amount: transfer.amount(),
                    asset,
                }
            })
            .collect()
    }
}

fn transact_case() -> impl Strategy<Value = TransactCase> {
    (
        prop::collection::vec(pubkey(), 1..=8),
        prop::collection::vec(input_utxo(), 1..=5),
        prop::collection::vec(message_data(), 0..=3),
        prop::collection::vec(interface_transfer(), 0..=4),
        0..=MAX_FIRST_QUEUE_SEQ,
        any::<u64>(),
        prop::sample::select(vec![
            tag::TRANSACT,
            tag::RING_TRANSACT,
            tag::RING_AUTHORITY_TRANSACT,
        ]),
    )
        .prop_flat_map(
            |(
                prefix,
                inputs,
                messages,
                interface_transfers,
                first_input_queue_seq,
                first_output_leaf_index,
                source_tag,
            )| {
                let prefix_len = prefix.len();
                let settlement_len: usize =
                    interface_transfers.iter().map(settlement_group_size).sum();
                let outputs = prop::collection::vec(transact_output(prefix_len), 0..=8);
                let settlement_accounts = prop::collection::vec(pubkey(), settlement_len);
                (outputs, settlement_accounts).prop_map(move |(outputs, settlement_accounts)| {
                    let mut accounts = prefix.clone();
                    accounts.extend(settlement_accounts);
                    TransactCase {
                        accounts,
                        prefix_len,
                        inputs: inputs.clone(),
                        outputs,
                        messages: messages.clone(),
                        interface_transfers: interface_transfers.clone(),
                        first_input_queue_seq,
                        first_output_leaf_index,
                        source_tag,
                    }
                })
            },
        )
}

fn expected_inputs<'a>(
    nullifiers: impl Iterator<Item = &'a [u8; 32]>,
    first_input_queue_seq: u64,
) -> Vec<Input> {
    nullifiers
        .enumerate()
        .map(|(position, nullifier)| Input {
            tree: INPUT_TREE,
            input_queue_seq: first_input_queue_seq + u64::try_from(position).expect("test shape"),
            nullifier: *nullifier,
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A direct `transact` is the outer instruction; a ring tag is CPI'd from a
    /// ring program, so the SPP instruction is inner and the event one level
    /// deeper. Both shapes must locate the event and rebuild against the SPP
    /// instruction's account list.
    #[test]
    fn transact_reconstruction_mirrors_instruction_data(case in transact_case()) {
        let spp = Pubkey::new_unique();
        let ix = transact_ix(
            case.inputs.clone(),
            case.outputs.clone(),
            case.messages.clone(),
            case.interface_transfers.clone(),
        );
        let event = TransactEvent {
            input_trees: vec![InputTreeSequence {
                tree: INPUT_TREE,
                first_input_queue_seq: case.first_input_queue_seq,
            }],
            output_tree: OUTPUT_TREE,
            first_output_leaf_index: case.first_output_leaf_index,
        };

        let outputs = case
            .outputs
            .iter()
            .map(|output| OutputUtxo {
                view_tag: match output.owner_tag {
                    OwnerTag::Inline(bytes) => bytes,
                    OwnerTag::Account(index) => case
                        .accounts
                        .get(usize::from(index))
                        .expect("strategy bounds the index")
                        .to_bytes(),
                },
                utxo_hash: output.utxo_hash,
                data: output.data.clone().unwrap_or_default(),
            })
            .collect();
        let expected = GeneralEvent {
            inputs: expected_inputs(
                case.inputs.iter().map(|input| &input.nullifier_hash),
                case.first_input_queue_seq,
            ),
            outputs,
            messages: case.messages.clone(),
            tx_viewing_pk: TX_VIEWING_PK,
            salt: SALT,
            first_output_leaf_index: case.first_output_leaf_index,
            output_tree: OUTPUT_TREE,
            spl_transfers: case.expected_spl_transfers(),
        };

        let group = if case.source_tag == tag::TRANSACT {
            InstructionGroup {
                outer: transact_source(spp, case.source_tag, case.accounts.clone(), &ix, 1),
                inner: vec![emit_instruction(spp, EventKind::Transact, &event, 2)],
            }
        } else {
            let ring = Pubkey::new_unique();
            InstructionGroup {
                outer: ParsedInstruction::new(ring, vec![spp], vec![case.source_tag], 1),
                inner: vec![
                    transact_source(spp, case.source_tag, case.accounts.clone(), &ix, 2),
                    emit_instruction(spp, EventKind::Transact, &event, 3),
                ],
            }
        };

        let events = indexed_events_from_instruction_groups(spp, &[group]);
        prop_assert_eq!(
            events.iter().map(|event| event.decoded.clone()).collect::<Vec<_>>(),
            vec![Ok(expected)]
        );
    }

    #[test]
    fn merge_reconstruction_mirrors_instruction_data(
        nullifiers in prop::collection::vec(any::<[u8; 32]>(), MERGE_DEFAULT_INPUT_COUNT),
        output_utxo_hash in any::<[u8; 32]>(),
        output_view_tag in any::<[u8; 32]>(),
        first_input_queue_seq in 0..=MAX_FIRST_QUEUE_SEQ,
        output_leaf_index in any::<u64>(),
        ring_data_hash in prop::option::of(any::<[u8; 32]>()),
    ) {
        let spp = Pubkey::new_unique();
        let mut merge = merge_ix(output_utxo_hash);
        merge.nullifiers = nullifiers.clone();
        let (source_tag, ix_bytes, output_data) = match ring_data_hash {
            None => (
                tag::MERGE_TRANSACT,
                merge.serialize().expect("serialize merge"),
                Vec::new(),
            ),
            Some(ring_data_hash) => {
                let mut ring = merge_ring_ix(output_utxo_hash, ring_data_hash);
                ring.merge = merge;
                (
                    tag::RING_MERGE_TRANSACT,
                    ring.serialize().expect("serialize merge ring"),
                    ring_data_hash.to_vec(),
                )
            }
        };
        let src = source(spp, source_tag, Vec::new(), ix_bytes, 1);
        let event = MergeEvent {
            input_trees: vec![InputTreeSequence {
                tree: INPUT_TREE,
                first_input_queue_seq,
            }],
            output_tree: OUTPUT_TREE,
            output_leaf_index,
            output_view_tag,
        };

        let expected = GeneralEvent {
            inputs: expected_inputs(nullifiers.iter(), first_input_queue_seq),
            outputs: vec![OutputUtxo {
                view_tag: output_view_tag,
                utxo_hash: output_utxo_hash,
                data: output_data,
            }],
            messages: Vec::new(),
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            first_output_leaf_index: output_leaf_index,
            output_tree: OUTPUT_TREE,
            spl_transfers: Vec::new(),
        };

        prop_assert_eq!(
            reconstruct_general_event(&src, &emit_event_data(EventKind::Merge, &event)),
            Ok(expected)
        );
    }

    #[test]
    fn arbitrary_source_and_event_bytes_never_panic(
        source_data in prop::collection::vec(any::<u8>(), 0..1024),
        accounts in prop::collection::vec(pubkey(), 0..8),
        emit_data in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let spp = Pubkey::new_unique();
        let src = ParsedInstruction::new(spp, accounts, source_data, 1);
        let _ = reconstruct_general_event(&src, &emit_data);
    }

    /// A well-formed event under arbitrary source bytes exercises the
    /// instruction-data parsers behind every event kind.
    #[test]
    fn valid_event_under_arbitrary_source_never_panics(
        source_data in prop::collection::vec(any::<u8>(), 0..1024),
        accounts in prop::collection::vec(pubkey(), 0..8),
        kind in prop::sample::select(vec![EventKind::Transact, EventKind::Merge]),
    ) {
        let spp = Pubkey::new_unique();
        let src = ParsedInstruction::new(spp, accounts, source_data, 1);
        let emit_data = match kind {
            EventKind::Transact => emit_event_data(
                kind,
                &TransactEvent {
                    input_trees: support::input_trees(0),
                    output_tree: OUTPUT_TREE,
                    first_output_leaf_index: 0,
                },
            ),
            _ => emit_event_data(kind, &support::merge_event([0u8; 32])),
        };
        let _ = reconstruct_general_event(&src, &emit_data);
    }
}
