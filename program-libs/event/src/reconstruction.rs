//! Rebuild the rich event an indexer consumes from the parent instruction.
//!
//! `transact` and `merge` emit only what execution assigns: the first nullifier
//! queue sequence and the first output leaf index. Everything else an indexer
//! needs is already in the instruction that emitted the event, so it is
//! reconstructed here rather than copied into the log. That keeps large shapes
//! affordable: the emitted event is a fixed 18 or 50 bytes instead of one entry
//! per input, output and message.
//!
//! Reconstruction parses instruction data and resolves owner tags, so it reads
//! `zolana-interface`'s wire types; the event crate owns it because the result
//! is an event, not an instruction.

use zolana_interface::instruction::{
    instruction_data::{
        merge_ring::MergeRingIxData,
        merge_transact::{MergeTransactIxData, MERGE_SUPPORTED_INPUT_COUNTS},
        transact::{
            fetch_tag, validate_interface_transfers, CircuitId, InterfaceTransfer, TransactIxData,
        },
    },
    tag,
};

use crate::{EventKind, GeneralEvent, Input, MergeEvent, OutputUtxo, SplTransfer, TransactEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconstructError {
    /// The parent instruction data did not parse as the tag claims.
    InvalidParentInstruction,
    /// The event envelope or its kind-specific body is malformed.
    InvalidEventPayload,
    /// An `OwnerTag::Account` referenced an index the account list does not have.
    OwnerTagAccountMissing,
    /// The parent account list is shorter than the instruction's fixed prefix.
    MissingAccount,
    /// The parent account count is not one the program accepts for this shape.
    InvalidAccountCount,
    /// The tag is not one that emits a reconstructible event.
    UnsupportedSourceInstruction(u8),
    /// The event kind is unknown or does not reconstruct to a [`GeneralEvent`].
    UnsupportedEventKind(u8),
    /// The event envelope does not match the instruction that emitted it.
    MismatchedEventKind {
        source_instruction_tag: u8,
        event_kind: u8,
    },
    /// A queue sequence or leaf index overflowed while deriving entry `i`.
    IndexOverflow,
}

/// Account positions the reconstruction reads. These are fixed prefixes of each
/// instruction's account list, so they hold for every rail of that instruction.
const TRANSACT_INPUT_TREE: usize = 1;
const TRANSACT_OUTPUT_TREE: usize = 2;
const MERGE_INPUT_TREE: usize = 0;
const MERGE_OUTPUT_TREE: usize = 1;

/// Number of accounts each settlement leg contributes, and where its mint sits
/// inside that group. Mirrors the program's per-kind parsing order.
fn settlement_group(transfer: &InterfaceTransfer) -> (usize, Option<usize>) {
    match transfer {
        // sol_interface, recipient
        InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. } => (2, None),
        // mint, spl_interface, token_authority, user_token_account, token_program
        InterfaceTransfer::SplDeposit { .. } => (5, Some(0)),
        // cpi_authority, mint, spl_interface, user_token_account, token_program
        InterfaceTransfer::SplWithdrawal { .. } => (5, Some(1)),
    }
}

fn validate_transact_source_tag(source_instruction_tag: u8) -> Result<(), ReconstructError> {
    if EventKind::for_source_instruction(source_instruction_tag) == Some(EventKind::Transact) {
        Ok(())
    } else {
        Err(ReconstructError::UnsupportedSourceInstruction(
            source_instruction_tag,
        ))
    }
}

fn validate_transact_shape(
    source_instruction_tag: u8,
    ix: &TransactIxData,
    account_count: usize,
) -> Result<(), ReconstructError> {
    let valid_circuit = match source_instruction_tag {
        tag::TRANSACT => matches!(ix.circuit, CircuitId::ConfidentialEddsa(..)),
        tag::RING_TRANSACT => {
            matches!(
                ix.circuit,
                CircuitId::RingEddsa(..) | CircuitId::RingP256(..)
            )
        }
        tag::RING_AUTHORITY_TRANSACT => ix.circuit.is_authority(),
        other => return Err(ReconstructError::UnsupportedSourceInstruction(other)),
    };
    if !valid_circuit
        || !ix.circuit.is_supported()
        || usize::from(ix.circuit.num_inputs()) != ix.inputs.len()
        || usize::from(ix.circuit.num_outputs()) != ix.outputs.len()
        || validate_interface_transfers(&ix.interface_transfers).is_err()
    {
        return Err(ReconstructError::InvalidParentInstruction);
    }

    let fixed_prefix = if source_instruction_tag == tag::TRANSACT {
        5usize
    } else {
        6usize
    };
    let settlement_count = ix
        .interface_transfers
        .iter()
        .try_fold(0usize, |total, transfer| {
            total.checked_add(settlement_group(transfer).0)
        });
    let base = settlement_count
        .and_then(|settlements| {
            fixed_prefix
                .checked_add(ix.inputs.len())?
                .checked_add(settlements)
        })
        .ok_or(ReconstructError::InvalidAccountCount)?;

    let valid_count = if source_instruction_tag == tag::RING_AUTHORITY_TRANSACT {
        account_count == base
    } else {
        base.checked_add(ix.inputs.len())
            .is_some_and(|maximum| (base..=maximum).contains(&account_count))
    };
    if !valid_count {
        return Err(ReconstructError::InvalidAccountCount);
    }
    Ok(())
}

/// Rebuild a `transact` event. `parent_data` includes the instruction tag byte.
///
/// Settlement legs are recovered without needing signer flags: the program
/// rejects any account past the last settlement group, so the settlement region
/// ends at the account list's end, and each leg's group size is a function of
/// its kind. The owner-signer run in between is simply skipped.
pub fn reconstruct_transact_event(
    source_instruction_tag: u8,
    parent_data: &[u8],
    parent_accounts: &[[u8; 32]],
    event: &TransactEvent,
) -> Result<GeneralEvent, ReconstructError> {
    validate_transact_source_tag(source_instruction_tag)?;
    let payload = parent_payload(source_instruction_tag, parent_data)?;
    let ix = TransactIxData::deserialize(payload)
        .map_err(|_| ReconstructError::InvalidParentInstruction)?;
    validate_transact_shape(source_instruction_tag, &ix, parent_accounts.len())?;

    let input_tree = *account_at(parent_accounts, TRANSACT_INPUT_TREE)?;
    let output_tree = *account_at(parent_accounts, TRANSACT_OUTPUT_TREE)?;
    let spl_transfers = settlement_transfers(&ix.interface_transfers, parent_accounts)?;

    let mut inputs = Vec::with_capacity(ix.inputs.len());
    for (offset, input) in ix.inputs.iter().enumerate() {
        inputs.push(Input {
            tree: input_tree,
            input_queue_seq: sequence_at(event.first_input_queue_seq, offset)?,
            nullifier: input.nullifier_hash,
        });
    }

    let mut outputs = Vec::with_capacity(ix.outputs.len());
    for output in ix.outputs {
        let view_tag = fetch_tag(&output.owner_tag, |index| {
            parent_accounts.get(usize::from(index)).copied()
        })
        .map_err(|_| ReconstructError::OwnerTagAccountMissing)?;
        outputs.push(OutputUtxo {
            view_tag,
            utxo_hash: output.utxo_hash,
            data: output.data.unwrap_or_default(),
        });
    }

    Ok(GeneralEvent {
        inputs,
        outputs,
        messages: ix.messages,
        tx_viewing_pk: ix.tx_viewing_pk,
        salt: ix.salt,
        first_output_leaf_index: event.first_output_leaf_index,
        output_tree,
        spl_transfers,
    })
}

/// Pair each interface transfer with its settlement account group.
fn settlement_transfers(
    transfers: &[InterfaceTransfer],
    parent_accounts: &[[u8; 32]],
) -> Result<Vec<SplTransfer>, ReconstructError> {
    if transfers.is_empty() {
        return Ok(Vec::new());
    }
    let total: usize = transfers
        .iter()
        .map(|transfer| settlement_group(transfer).0)
        .sum();
    // The settlement region is the tail of the account list: the program refuses
    // to run with any account after the last group.
    let mut offset = parent_accounts
        .len()
        .checked_sub(total)
        .ok_or(ReconstructError::MissingAccount)?;

    let mut out = Vec::with_capacity(transfers.len());
    for transfer in transfers {
        let (size, mint_offset) = settlement_group(transfer);
        let asset = match mint_offset {
            None => None,
            Some(within) => Some(*account_at(parent_accounts, offset + within)?),
        };
        out.push(SplTransfer {
            is_deposit: transfer.is_deposit(),
            amount: transfer.amount(),
            asset,
        });
        offset += size;
    }
    Ok(out)
}

/// Rebuild a merge event. `parent_data` includes the instruction tag byte, which
/// also selects where the merge payload starts: `ring_merge_transact` prefixes a
/// 32-byte `output_ring_data_hash` that `merge_transact` does not have.
pub fn reconstruct_merge_event(
    source_instruction_tag: u8,
    parent_data: &[u8],
    parent_accounts: &[[u8; 32]],
    event: &MergeEvent,
) -> Result<GeneralEvent, ReconstructError> {
    let payload = parent_payload(source_instruction_tag, parent_data)?;
    let (ring_data_hash, ix) = match source_instruction_tag {
        tag::MERGE_TRANSACT => (
            None,
            MergeTransactIxData::deserialize(payload)
                .map_err(|_| ReconstructError::InvalidParentInstruction)?,
        ),
        tag::RING_MERGE_TRANSACT => {
            let ring = MergeRingIxData::deserialize(payload)
                .map_err(|_| ReconstructError::InvalidParentInstruction)?;
            (Some(ring.output_ring_data_hash), ring.merge)
        }
        other => return Err(ReconstructError::UnsupportedSourceInstruction(other)),
    };

    let input_count = ix.nullifiers.len();
    if ix.utxo_tree_root_index.len() != input_count
        || ix.nullifier_tree_root_index.len() != input_count
        || !MERGE_SUPPORTED_INPUT_COUNTS.contains(&input_count)
    {
        return Err(ReconstructError::InvalidParentInstruction);
    }
    let expected_accounts = 6usize
        .checked_add(input_count)
        .ok_or(ReconstructError::InvalidAccountCount)?;
    if parent_accounts.len() != expected_accounts {
        return Err(ReconstructError::InvalidAccountCount);
    }

    let input_tree = *account_at(parent_accounts, MERGE_INPUT_TREE)?;
    let output_tree = *account_at(parent_accounts, MERGE_OUTPUT_TREE)?;

    let mut inputs = Vec::with_capacity(ix.nullifiers.len());
    for (offset, nullifier) in ix.nullifiers.iter().enumerate() {
        inputs.push(Input {
            tree: input_tree,
            input_queue_seq: sequence_at(event.first_input_queue_seq, offset)?,
            nullifier: *nullifier,
        });
    }

    // The merged output carries no ciphertext: a wallet reconstructs it from
    // `nullifiers[0]` and the spent inputs. `ring_merge_transact` publishes its
    // `output_ring_data_hash` there instead, and takes its view tag from
    // `nullifiers[0]` rather than from the retained event field.
    let (view_tag, data) = match ring_data_hash {
        None => (event.output_view_tag, Vec::new()),
        Some(hash) => (
            *ix.nullifiers
                .first()
                .ok_or(ReconstructError::InvalidParentInstruction)?,
            hash.to_vec(),
        ),
    };

    Ok(GeneralEvent {
        inputs,
        outputs: vec![OutputUtxo {
            view_tag,
            utxo_hash: ix.output_utxo_hash,
            data,
        }],
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: event.first_output_leaf_index,
        output_tree,
        spl_transfers: Vec::new(),
    })
}

fn account_at(accounts: &[[u8; 32]], index: usize) -> Result<&[u8; 32], ReconstructError> {
    accounts.get(index).ok_or(ReconstructError::MissingAccount)
}

fn parent_payload(
    source_instruction_tag: u8,
    parent_data: &[u8],
) -> Result<&[u8], ReconstructError> {
    let (&actual_tag, payload) = parent_data
        .split_first()
        .ok_or(ReconstructError::InvalidParentInstruction)?;
    if actual_tag != source_instruction_tag {
        return Err(ReconstructError::InvalidParentInstruction);
    }
    Ok(payload)
}

fn sequence_at(first: u64, offset: usize) -> Result<u64, ReconstructError> {
    u64::try_from(offset)
        .ok()
        .and_then(|offset| first.checked_add(offset))
        .ok_or(ReconstructError::IndexOverflow)
}

/// Rebuild the rich event for any emitting instruction, dispatching on the kind
/// byte the payload carries.
///
/// `payload` is the `EMIT_EVENT` instruction data with its tag byte removed, so
/// it is `[EventKind, borsh(body)]`. Deposits still log a whole `GeneralEvent`;
/// `transact` and `merge` log only their assigned positions and are rebuilt from
/// `parent_data` and `parent_accounts`.
pub fn general_event_from_site(
    source_instruction_tag: u8,
    parent_data: &[u8],
    parent_accounts: &[[u8; 32]],
    payload: &[u8],
) -> Result<GeneralEvent, ReconstructError> {
    use borsh::BorshDeserialize;

    // Validate the caller-supplied source tag against the actual parent even
    // for deposits, whose event body does not otherwise need parent data.
    let _ = parent_payload(source_instruction_tag, parent_data)?;
    let (&kind_byte, body) = payload
        .split_first()
        .ok_or(ReconstructError::InvalidEventPayload)?;
    let kind =
        EventKind::from_byte(kind_byte).ok_or(ReconstructError::UnsupportedEventKind(kind_byte))?;
    let expected_kind = EventKind::for_source_instruction(source_instruction_tag).ok_or(
        ReconstructError::UnsupportedSourceInstruction(source_instruction_tag),
    )?;
    if kind != expected_kind {
        return Err(ReconstructError::MismatchedEventKind {
            source_instruction_tag,
            event_kind: kind_byte,
        });
    }

    match kind {
        EventKind::Transact => {
            let event = TransactEvent::try_from_slice(body)
                .map_err(|_| ReconstructError::InvalidEventPayload)?;
            reconstruct_transact_event(source_instruction_tag, parent_data, parent_accounts, &event)
        }
        EventKind::Merge => {
            let event = MergeEvent::try_from_slice(body)
                .map_err(|_| ReconstructError::InvalidEventPayload)?;
            reconstruct_merge_event(source_instruction_tag, parent_data, parent_accounts, &event)
        }
        // Deposits are out of scope for the shrink: their outputs are
        // Poseidon-hashed on chain and re-encoded rather than republished, so
        // the body still carries everything.
        EventKind::Deposit => {
            GeneralEvent::try_from_slice(body).map_err(|_| ReconstructError::InvalidEventPayload)
        }
        EventKind::NullifierTreeUpdate => Err(ReconstructError::UnsupportedEventKind(kind_byte)),
    }
}
