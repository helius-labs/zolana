//! Rebuild the rich event an indexer consumes from the parent instruction.
//!
//! `transact` and `merge` emit only what execution assigns: the first nullifier
//! queue sequence and the first output leaf index. Everything else an indexer
//! needs is already in the instruction that emitted the event, so it is
//! reconstructed here rather than copied into the log. That keeps large shapes
//! affordable: the emitted event is a fixed 18 or 50 bytes instead of one entry
//! per input, output and message.
//!
//! This lives in `zolana-interface` rather than `zolana-event` because it parses
//! instruction data and resolves owner tags, and `zolana-interface` already
//! depends on `zolana-event` — the other direction would not compile.

use zolana_event::{
    GeneralEvent, Input, MergeEvent, MessageData, OutputUtxo, SplTransfer, TransactEvent,
};

use crate::instruction::instruction_data::merge_transact::MergeTransactIxDataRef;
use crate::instruction::instruction_data::transact::{
    fetch_tag, InterfaceTransfer, TransactIxDataRef,
};
use crate::instruction::tag;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconstructError {
    /// The parent instruction data did not parse as the tag claims.
    UnparsableParent,
    /// An `OwnerTag::Account` referenced an index the account list does not have.
    OwnerTagAccountMissing,
    /// The parent account list is shorter than the instruction's fixed prefix.
    MissingAccount,
    /// The tag is not one that emits a reconstructible event.
    UnsupportedInstruction(u8),
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

/// Accounts before the nullifier PDAs: payer, input tree, output tree, the pool
/// program, the system program, and for the ring rails the signing ring config.
fn fixed_prefix_len(source_instruction_tag: u8) -> Result<usize, ReconstructError> {
    match source_instruction_tag {
        tag::TRANSACT => Ok(5),
        tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT => Ok(6),
        other => Err(ReconstructError::UnsupportedInstruction(other)),
    }
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
    let payload = parent_data
        .get(1..)
        .ok_or(ReconstructError::UnparsableParent)?;
    let ix =
        TransactIxDataRef::from_bytes(payload).map_err(|_| ReconstructError::UnparsableParent)?;

    let input_tree = *account_at(parent_accounts, TRANSACT_INPUT_TREE)?;
    let output_tree = *account_at(parent_accounts, TRANSACT_OUTPUT_TREE)?;

    let mut inputs = Vec::with_capacity(ix.tail.inputs.len());
    for (offset, input) in ix.tail.inputs.iter().enumerate() {
        inputs.push(Input {
            tree: input_tree,
            input_queue_seq: sequence_at(event.first_input_queue_seq, offset)?,
            nullifier: input.nullifier_hash,
        });
    }

    let mut outputs = Vec::with_capacity(ix.bound.outputs.len());
    for output in &ix.bound.outputs {
        let view_tag = fetch_tag(&output.owner_tag, |index| {
            parent_accounts.get(usize::from(index)).copied()
        })
        .map_err(|_| ReconstructError::OwnerTagAccountMissing)?;
        outputs.push(OutputUtxo {
            view_tag,
            utxo_hash: *output.utxo_hash,
            data: output.data.map(<[u8]>::to_vec).unwrap_or_default(),
        });
    }

    Ok(GeneralEvent {
        inputs,
        outputs,
        messages: ix
            .bound
            .messages
            .iter()
            .map(|message| MessageData {
                view_tag: *message.view_tag,
                data: message.data.to_vec(),
            })
            .collect(),
        tx_viewing_pk: *ix.bound.tx_viewing_pk,
        salt: *ix.bound.salt,
        first_output_leaf_index: event.first_output_leaf_index,
        output_tree,
        spl_transfers: settlement_transfers(
            source_instruction_tag,
            &ix.bound.interface_transfers,
            parent_accounts,
        )?,
    })
}

/// Pair each interface transfer with its settlement account group.
fn settlement_transfers(
    source_instruction_tag: u8,
    transfers: &[InterfaceTransfer],
    parent_accounts: &[[u8; 32]],
) -> Result<Vec<SplTransfer>, ReconstructError> {
    if transfers.is_empty() {
        return Ok(Vec::new());
    }
    let _ = fixed_prefix_len(source_instruction_tag)?;
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
    let payload = parent_data
        .get(1..)
        .ok_or(ReconstructError::UnparsableParent)?;
    let (ring_data_hash, merge_payload) = match source_instruction_tag {
        tag::MERGE_TRANSACT => (None, payload),
        tag::RING_MERGE_TRANSACT => {
            let hash: [u8; 32] = payload
                .get(..32)
                .ok_or(ReconstructError::UnparsableParent)?
                .try_into()
                .map_err(|_| ReconstructError::UnparsableParent)?;
            (
                Some(hash),
                payload
                    .get(32..)
                    .ok_or(ReconstructError::UnparsableParent)?,
            )
        }
        other => return Err(ReconstructError::UnsupportedInstruction(other)),
    };
    let ix = MergeTransactIxDataRef::from_bytes(merge_payload)
        .map_err(|_| ReconstructError::UnparsableParent)?;

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
                .ok_or(ReconstructError::UnparsableParent)?,
            hash.to_vec(),
        ),
    };

    Ok(GeneralEvent {
        inputs,
        outputs: vec![OutputUtxo {
            view_tag,
            utxo_hash: *ix.output_utxo_hash,
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

fn sequence_at(first: u64, offset: usize) -> Result<u64, ReconstructError> {
    u64::try_from(offset)
        .ok()
        .and_then(|offset| first.checked_add(offset))
        .ok_or(ReconstructError::IndexOverflow)
}

/// Rebuild the rich event for any emitting instruction, dispatching on the kind
/// byte the payload carries.
///
/// Behind `borsh` because decoding the logged body needs it; the on-chain
/// program never decodes events, only emits them.
///
/// `payload` is the `EMIT_EVENT` instruction data with its tag byte removed, so
/// it is `[EventKind, borsh(body)]`. Deposits still log a whole `GeneralEvent`;
/// `transact` and `merge` log only their assigned positions and are rebuilt from
/// `parent_data` and `parent_accounts`.
#[cfg(feature = "borsh")]
pub fn general_event_from_site(
    source_instruction_tag: u8,
    parent_data: &[u8],
    parent_accounts: &[[u8; 32]],
    payload: &[u8],
) -> Result<GeneralEvent, ReconstructError> {
    use borsh::BorshDeserialize;
    use zolana_event::EventKind;

    let (&kind_byte, body) = payload
        .split_first()
        .ok_or(ReconstructError::UnparsableParent)?;
    let kind = EventKind::from_byte(kind_byte)
        .ok_or(ReconstructError::UnsupportedInstruction(kind_byte))?;

    match kind {
        EventKind::Transact => {
            let event = TransactEvent::try_from_slice(body)
                .map_err(|_| ReconstructError::UnparsableParent)?;
            reconstruct_transact_event(source_instruction_tag, parent_data, parent_accounts, &event)
        }
        EventKind::Merge => {
            let event =
                MergeEvent::try_from_slice(body).map_err(|_| ReconstructError::UnparsableParent)?;
            reconstruct_merge_event(source_instruction_tag, parent_data, parent_accounts, &event)
        }
        // Deposits are out of scope for the shrink: their outputs are
        // Poseidon-hashed on chain and re-encoded rather than republished, so
        // the body still carries everything.
        EventKind::Deposit => {
            GeneralEvent::try_from_slice(body).map_err(|_| ReconstructError::UnparsableParent)
        }
        EventKind::NullifierTreeUpdate => Err(ReconstructError::UnsupportedInstruction(kind_byte)),
    }
}
