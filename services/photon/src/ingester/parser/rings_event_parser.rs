use super::event_site::{find_event_sites, to_rings_instruction_groups};
use super::state_update::{
    RingsMessageUpdate, RingsNullifierUpdate, RingsOutputUpdate, RingsTransactionUpdate,
    StateUpdate,
};
use crate::ingester::{error::IngesterError, typedefs::block_info::TransactionInfo};
use zolana_event::{decode_event_payload, tag};
use zolana_interface::pda;

const RINGS_PARSE_VERSION: i16 = 3;

pub fn parse_rings_events(
    tx: &TransactionInfo,
    slot: u64,
) -> Result<Option<StateUpdate>, IngesterError> {
    let rings_program_id = pda::shielded_pool_program_id();
    let groups = to_rings_instruction_groups(&tx.instruction_groups);
    let event_sites = find_event_sites(&groups, rings_program_id, is_general_event_source)?;

    if event_sites.is_empty() {
        return Ok(None);
    }

    let mut state_update = StateUpdate::new();

    for (event_index, event_site) in event_sites.into_iter().enumerate() {
        let event_index_i16 = i16::try_from(event_index).map_err(|_| {
            IngesterError::ParserError(format!("Event index {} does not fit in i16", event_index))
        })?;
        let event = decode_event_payload(&event_site.payload).map_err(|err| {
            IngesterError::ParserError(format!(
                "Failed to decode Rings event for {} event {}: {:?}",
                tx.signature, event_index, err
            ))
        })?;
        let tx_viewing_pk = Some(event.tx_viewing_pk)
            .filter(|key| key.iter().any(|byte| *byte != 0))
            .map(|key| key.to_vec());
        let salt = Some(event.salt)
            .filter(|salt| salt.iter().any(|byte| *byte != 0))
            .map(|salt| salt.to_vec());

        let proofless = matches!(
            event_site.source_instruction_tag,
            tag::DEPOSIT | tag::RING_DEPOSIT
        );

        let outputs = event
            .outputs
            .iter()
            .enumerate()
            .map(|(output_index, output)| {
                let output_index_i16 = i16::try_from(output_index).map_err(|_| {
                    IngesterError::ParserError(format!(
                        "Output index {} does not fit in i16",
                        output_index
                    ))
                })?;
                let output_index_u64 = u64::try_from(output_index).map_err(|_| {
                    IngesterError::ParserError(format!(
                        "Output index {} does not fit in u64",
                        output_index
                    ))
                })?;
                Ok(RingsOutputUpdate {
                    output_index: output_index_i16,
                    output_tree: event.output_tree,
                    leaf_index: event
                        .first_output_leaf_index
                        .checked_add(output_index_u64)
                        .ok_or_else(|| {
                            IngesterError::ParserError(format!(
                                "Output leaf index overflowed for base {} and output index {}",
                                event.first_output_leaf_index, output_index
                            ))
                        })?,
                    view_tag: output.view_tag,
                    utxo_hash: output.utxo_hash,
                    payload: output.data.clone(),
                })
            })
            .collect::<Result<Vec<_>, IngesterError>>()?;

        let messages = event
            .messages
            .iter()
            .enumerate()
            .map(|(message_index, message)| {
                Ok(RingsMessageUpdate {
                    message_index: i16::try_from(message_index).map_err(|_| {
                        IngesterError::ParserError(format!(
                            "Message index {} does not fit in i16",
                            message_index
                        ))
                    })?,
                    view_tag: message.view_tag,
                    payload: message.data.clone(),
                })
            })
            .collect::<Result<Vec<_>, IngesterError>>()?;

        let nullifiers = event
            .inputs
            .iter()
            .enumerate()
            .map(|(input_index, input)| {
                Ok(RingsNullifierUpdate {
                    input_index: i16::try_from(input_index).map_err(|_| {
                        IngesterError::ParserError(format!(
                            "Input index {} does not fit in i16",
                            input_index
                        ))
                    })?,
                    nullifier_tree: input.tree,
                    input_queue_seq: input.input_queue_seq,
                    nullifier: input.nullifier,
                })
            })
            .collect::<Result<Vec<_>, IngesterError>>()?;

        state_update
            .rings_transactions
            .push(RingsTransactionUpdate {
                signature: tx.signature,
                event_index: event_index_i16,
                slot,
                ring_config: event_site.ring_config.map(|key| key.to_bytes()),
                source_instruction_tag: event_site.source_instruction_tag as i16,
                // Accepted events are Rings EMIT_EVENT inner instructions under a
                // Rings source instruction, so these fields are trusted as the
                // program-authored event state rather than re-derived from accounts.
                output_tree: event.output_tree,
                first_output_leaf_index: event.first_output_leaf_index,
                tx_viewing_pk,
                salt,
                proofless,
                encrypted_utxos: None,
                raw_event: Some(event_site.payload),
                parse_version: RINGS_PARSE_VERSION,
                outputs,
                messages,
                nullifiers,
            });
    }

    Ok(Some(state_update))
}

fn is_general_event_source(source_instruction_tag: u8) -> bool {
    // Keep this in sync with shielded-pool processors that call
    // `emit_general_event`, directly or via process_transact_core /
    // process_merge_core. Self-emitting instructions: TRANSACT, RING_TRANSACT,
    // RING_AUTHORITY_TRANSACT (transact core); MERGE_TRANSACT, RING_MERGE_TRANSACT
    // (merge core); DEPOSIT, RING_DEPOSIT (deposit). Missing a tag here silently
    // drops those transactions from the index (they never get a rings_transactions
    // row).
    matches!(
        source_instruction_tag,
        tag::TRANSACT
            | tag::RING_TRANSACT
            | tag::RING_AUTHORITY_TRANSACT
            | tag::MERGE_TRANSACT
            | tag::RING_MERGE_TRANSACT
            | tag::DEPOSIT
            | tag::RING_DEPOSIT
    )
}
