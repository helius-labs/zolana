//! Rebuild the `GeneralEvent` view from an `EMIT_EVENT` payload and the
//! instruction that emitted it. The transact/merge reconstruction mirrors what
//! the program used to write into the event field for field: outputs 1:1 with
//! the instruction's outputs under their resolved owner tag, messages verbatim,
//! and queue sequence numbers counted up from the first sequence emitted for
//! each input's own tree.

use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;
use zolana_event::{
    tag, EventKind, GeneralEvent, Input, InputTreeSequence, MergeEvent, MessageData, OutputUtxo,
    SplTransfer, TransactEvent,
};
use zolana_interface::instruction::instruction_data::{
    merge_ring::MergeRingIxDataRef,
    merge_transact::MergeTransactIxDataRef,
    transact::{InputUtxo, InterfaceTransfer, OwnerTag, TransactIxDataRef},
};

use crate::{instruction::ParsedInstruction, EventDecodeError};

/// Rebuild the [`GeneralEvent`] of one `EMIT_EVENT` self-CPI. `source` is the
/// instruction that emitted it (its data and account list are the second input
/// of the reconstruction); `emit_event_data` starts with [`tag::EMIT_EVENT`].
pub fn reconstruct_general_event(
    source: &ParsedInstruction,
    emit_event_data: &[u8],
) -> Result<GeneralEvent, EventDecodeError> {
    let (&instruction_tag, payload) = emit_event_data
        .split_first()
        .ok_or(EventDecodeError::MissingInstructionTag)?;
    if instruction_tag != tag::EMIT_EVENT {
        return Err(EventDecodeError::InvalidInstructionTag(instruction_tag));
    }
    reconstruct_general_event_from_payload(source, payload)
}

/// Same as [`reconstruct_general_event`] for `payload = [EventKind, borsh(body)]`,
/// the `EMIT_EVENT` instruction data without its tag byte.
pub fn reconstruct_general_event_from_payload(
    source: &ParsedInstruction,
    payload: &[u8],
) -> Result<GeneralEvent, EventDecodeError> {
    let (&kind_byte, body) = payload
        .split_first()
        .ok_or(EventDecodeError::InvalidPayload)?;
    let kind =
        EventKind::from_byte(kind_byte).ok_or(EventDecodeError::InvalidEventKind(kind_byte))?;
    match kind {
        EventKind::Deposit => {
            GeneralEvent::try_from_slice(body).map_err(|_| EventDecodeError::InvalidPayload)
        }
        EventKind::Transact => {
            let event = TransactEvent::try_from_slice(body)
                .map_err(|_| EventDecodeError::InvalidPayload)?;
            transact_general_event(source, &event)
        }
        EventKind::Merge => {
            let event =
                MergeEvent::try_from_slice(body).map_err(|_| EventDecodeError::InvalidPayload)?;
            merge_general_event(source, &event)
        }
        EventKind::NullifierTreeUpdate => Err(EventDecodeError::NotAGeneralEvent),
    }
}

/// Rebuild a `transact` event. `source` must be the SPP `transact`,
/// `ring_transact` or `ring_authority_transact` instruction (for ring CPIs the
/// SPP inner instruction, not the ring program's outer one): `OwnerTag::Account`
/// indexes resolve against its account list exactly as the program resolved them.
pub fn transact_general_event(
    source: &ParsedInstruction,
    event: &TransactEvent,
) -> Result<GeneralEvent, EventDecodeError> {
    let (source_tag, ix_bytes) = source_tag_and_data(source)?;
    if !matches!(
        source_tag,
        tag::TRANSACT | tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT
    ) {
        return Err(EventDecodeError::UnsupportedSourceInstruction(source_tag));
    }
    let ix = TransactIxDataRef::from_bytes(ix_bytes)
        .map_err(|_| EventDecodeError::InvalidSourceInstructionData)?;
    let spl_transfers = settlement_transfers(&ix.interface_transfers, &source.accounts)?;

    let inputs = inputs_from_tree_indexes(&event.input_trees, &ix.inputs)?;

    let outputs = ix
        .outputs
        .iter()
        .map(|output| {
            let resolved = output
                .into_resolved(|index| {
                    source
                        .accounts
                        .get(usize::from(index))
                        .map(|account| account.to_bytes())
                })
                .map_err(|_| match output.owner_tag {
                    OwnerTag::Account(index) => EventDecodeError::OutputOwnerAccountMissing(index),
                    OwnerTag::Inline(_) => EventDecodeError::InvalidSourceInstructionData,
                })?;
            Ok(OutputUtxo {
                view_tag: resolved.owner_tag,
                utxo_hash: *resolved.utxo_hash,
                data: resolved.data.map(<[u8]>::to_vec).unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, EventDecodeError>>()?;

    let messages = ix
        .messages
        .iter()
        .map(|message| MessageData {
            view_tag: *message.view_tag,
            data: message.data.to_vec(),
        })
        .collect();

    Ok(GeneralEvent {
        inputs,
        outputs,
        messages,
        tx_viewing_pk: *ix.tx_viewing_pk,
        salt: *ix.salt,
        first_output_leaf_index: event.first_output_leaf_index,
        output_tree: event.output_tree,
        spl_transfers,
    })
}

/// One [`SplTransfer`] per interface transfer, in leg order. `is_deposit` and
/// `amount` come from the transfer; the mint comes from the leg's settlement
/// group. The groups are the last accounts of the instruction, in leg order, and
/// the program rejects any account after them, so they are located from the end
/// of the account list; the owner signers before them need no counting.
fn settlement_transfers(
    transfers: &[InterfaceTransfer],
    accounts: &[Pubkey],
) -> Result<Vec<SplTransfer>, EventDecodeError> {
    let total = transfers
        .iter()
        .try_fold(0usize, |total, transfer| {
            total.checked_add(transfer.settlement_account_count())
        })
        .ok_or(EventDecodeError::IndexOverflow)?;
    let settlement_accounts = accounts
        .len()
        .checked_sub(total)
        .and_then(|start| accounts.get(start..))
        .ok_or(EventDecodeError::MissingSettlementAccount)?;

    let mut spl_transfers = Vec::with_capacity(transfers.len());
    let mut group_start = 0usize;
    for transfer in transfers {
        let asset = match transfer.mint_account_position() {
            None => None,
            Some(position) => Some(
                settlement_accounts
                    .get(group_start + position)
                    .ok_or(EventDecodeError::MissingSettlementAccount)?
                    .to_bytes(),
            ),
        };
        spl_transfers.push(SplTransfer {
            is_deposit: transfer.is_deposit(),
            amount: transfer.amount(),
            asset,
        });
        group_start += transfer.settlement_account_count();
    }
    Ok(spl_transfers)
}

/// Rebuild a `merge_transact` or `merge_ring` event. The single output carries
/// the emitted view tag, the instruction's `output_utxo_hash`, and, for
/// `merge_ring`, the output `ring_data_hash` as its payload.
pub fn merge_general_event(
    source: &ParsedInstruction,
    event: &MergeEvent,
) -> Result<GeneralEvent, EventDecodeError> {
    let (source_tag, ix_bytes) = source_tag_and_data(source)?;
    let (merge, output_data) = match source_tag {
        tag::MERGE_TRANSACT => {
            let merge = MergeTransactIxDataRef::from_bytes(ix_bytes)
                .map_err(|_| EventDecodeError::InvalidSourceInstructionData)?;
            (merge, Vec::new())
        }
        tag::RING_MERGE_TRANSACT => {
            let ring = MergeRingIxDataRef::from_bytes(ix_bytes)
                .map_err(|_| EventDecodeError::InvalidSourceInstructionData)?;
            let output_data = ring.output_ring_data_hash.to_vec();
            (ring.merge, output_data)
        }
        other => return Err(EventDecodeError::UnsupportedSourceInstruction(other)),
    };

    let input_tree = single_input_tree(&event.input_trees)?;
    let inputs = inputs_from_nullifiers(input_tree, merge.nullifiers.iter())?;

    Ok(GeneralEvent {
        inputs,
        outputs: vec![OutputUtxo {
            view_tag: event.output_view_tag,
            utxo_hash: *merge.output_utxo_hash,
            data: output_data,
        }],
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: event.output_leaf_index,
        output_tree: event.output_tree,
        spl_transfers: Vec::new(),
    })
}

fn source_tag_and_data(source: &ParsedInstruction) -> Result<(u8, &[u8]), EventDecodeError> {
    source
        .data
        .split_first()
        .map(|(tag_byte, data)| (*tag_byte, data))
        .ok_or(EventDecodeError::MissingInstructionTag)
}

/// `merge` spends from one tree and its instruction data carries no per-input
/// tree index, so every nullifier must belong to the one emitted tree.
fn single_input_tree(
    input_trees: &[InputTreeSequence],
) -> Result<InputTreeSequence, EventDecodeError> {
    match input_trees {
        [tree] => Ok(*tree),
        _ => Err(EventDecodeError::UnsupportedInputTreeCount(
            input_trees.len(),
        )),
    }
}

/// Assign every `transact` input its tree and queue sequence number. An input's
/// `tree_index` selects the emitted entry, which the program wrote in
/// `tree_contexts` order; its sequence is that entry's `first_input_queue_seq`
/// plus the number of earlier inputs on the same tree. The program groups
/// inputs by tree, so each tree's run is contiguous, but the running counters
/// do not rely on it.
fn inputs_from_tree_indexes(
    input_trees: &[InputTreeSequence],
    inputs: &[InputUtxo],
) -> Result<Vec<Input>, EventDecodeError> {
    if input_trees.is_empty() {
        return Err(EventDecodeError::UnsupportedInputTreeCount(0));
    }
    let mut spent_per_tree = vec![0u64; input_trees.len()];
    inputs
        .iter()
        .map(|input| {
            let position = usize::from(input.tree_index);
            let (tree, spent) = input_trees
                .get(position)
                .zip(spent_per_tree.get_mut(position))
                .ok_or(EventDecodeError::InputTreeIndexOutOfRange(input.tree_index))?;
            let input_queue_seq = tree
                .first_input_queue_seq
                .checked_add(*spent)
                .ok_or(EventDecodeError::IndexOverflow)?;
            *spent = spent
                .checked_add(1)
                .ok_or(EventDecodeError::IndexOverflow)?;
            Ok(Input {
                tree: tree.tree,
                input_queue_seq,
                nullifier: input.nullifier_hash,
            })
        })
        .collect()
}

fn inputs_from_nullifiers<'a>(
    tree: InputTreeSequence,
    nullifiers: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<Vec<Input>, EventDecodeError> {
    nullifiers
        .enumerate()
        .map(|(position, nullifier)| {
            let offset = u64::try_from(position).map_err(|_| EventDecodeError::IndexOverflow)?;
            let input_queue_seq = tree
                .first_input_queue_seq
                .checked_add(offset)
                .ok_or(EventDecodeError::IndexOverflow)?;
            Ok(Input {
                tree: tree.tree,
                input_queue_seq,
                nullifier: *nullifier,
            })
        })
        .collect()
}
