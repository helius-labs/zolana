use super::event_site::to_rings_instruction_groups;
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::{NullifierTreeBatchUpdate, StateUpdate};
use crate::ingester::typedefs::block_info::TransactionInfo;
use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;
use zolana_event::find_event_sites;
use zolana_interface::event::EventKind;
use zolana_interface::{instruction::tag, pda};
use zolana_tree::NullifierTreeUpdateEvent;

/// Read the nullifier-tree batch updates a transaction actually performed.
///
/// This must come from the emitted `NullifierTreeUpdateEvent` rather than from
/// the `BatchUpdateNullifierTree` instruction that carries it. The instruction
/// is a request: when its proof arrives out of order the program caches it and
/// applies nothing, and when it unblocks earlier cached proofs the program
/// applies several zkp batches at once. Only the event says which batches
/// landed and what the resulting root is.
pub fn parse_nullifier_tree_batch_updates(
    tx: &TransactionInfo,
) -> Result<Option<StateUpdate>, IngesterError> {
    if tx.error.is_some() {
        return Ok(None);
    }

    let groups = to_rings_instruction_groups(&tx.instruction_groups);
    let event_sites = find_event_sites(pda::shielded_pool_program_id(), &groups, |source| {
        source == tag::BATCH_UPDATE_NULLIFIER_TREE
    });
    if event_sites.is_empty() {
        return Ok(None);
    }

    let mut state_update = StateUpdate::new();

    for event_site in &event_sites {
        let Some(event) = decode_batch_address_append(event_site.payload, tx)? else {
            continue;
        };

        // `start_sequence_number` is the sequence number after the cascade's
        // first applied batch, and each further batch advances it by one.
        let sequence_number = event
            .start_sequence_number
            .checked_add(u64::from(event.num_update.saturating_sub(1)))
            .ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Batch append sequence number overflow in {}",
                    tx.signature
                ))
            })?;

        state_update
            .nullifier_tree_batch_updates
            .push(NullifierTreeBatchUpdate {
                tree: Pubkey::new_from_array(event.merkle_tree_pubkey),
                new_root: event.new_root,
                zkp_batch_size: u64::from(event.zkp_batch_size),
                num_update: event.num_update,
                sequence_number,
                signature: tx.signature,
            });
    }

    if state_update.nullifier_tree_batch_updates.is_empty() {
        return Ok(None);
    }
    Ok(Some(state_update))
}

/// Decode an event payload (`[kind, borsh(body)]`) as a batch append, or return
/// `None` for any other kind emitted under this instruction.
fn decode_batch_address_append(
    payload: &[u8],
    tx: &TransactionInfo,
) -> Result<Option<NullifierTreeUpdateEvent>, IngesterError> {
    let Some((kind, body)) = payload.split_first() else {
        return Ok(None);
    };
    if EventKind::from_byte(*kind) != Some(EventKind::NullifierTreeUpdate) {
        return Ok(None);
    }

    NullifierTreeUpdateEvent::try_from_slice(body)
        .map(Some)
        .map_err(|err| {
            IngesterError::ParserError(format!(
                "Failed to decode NullifierTreeUpdateEvent in {}: {}",
                tx.signature, err
            ))
        })
}

pub fn has_nullifier_tree_batch_update(tx: &TransactionInfo) -> bool {
    if tx.error.is_some() {
        return false;
    }

    tx.instruction_groups.iter().any(|instruction_group| {
        std::iter::once(&instruction_group.outer_instruction)
            .chain(instruction_group.inner_instructions.iter())
            .any(|instruction| {
                instruction.program_id == pda::shielded_pool_program_id()
                    && instruction.data.first() == Some(&tag::BATCH_UPDATE_NULLIFIER_TREE)
            })
    })
}
