use super::state_update::{
    RingsNullifierUpdate, RingsOutputUpdate, RingsTransactionUpdate, StateUpdate,
};
use crate::ingester::{
    error::IngesterError,
    typedefs::block_info::{
        Instruction as PhotonInstruction, InstructionGroup as PhotonInstructionGroup,
        TransactionInfo,
    },
};
use rings_event::{
    decode_event_payload, decode_output_data, tag, InstructionGroup as RingsInstructionGroup,
    ParsedInstruction as RingsInstruction,
};
use rings_interface::pda;
use solana_pubkey::Pubkey;

const RINGS_PARSE_VERSION: i16 = 1;

struct EventSite {
    source_instruction_tag: u8,
    payload: Vec<u8>,
}

pub fn parse_rings_events(
    tx: &TransactionInfo,
    slot: u64,
) -> Result<Option<StateUpdate>, IngesterError> {
    let rings_program_id = pda::shielded_pool_program_id();
    let groups = to_rings_instruction_groups(&tx.instruction_groups);
    let event_sites = find_event_sites(&groups, rings_program_id)?;

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

        let proofless = event
            .outputs
            .iter()
            .any(|output| decode_output_data(&output.data).is_ok());

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
                rings_program_id: rings_program_id.to_bytes(),
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
                nullifiers,
            });
    }

    Ok(Some(state_update))
}

fn to_rings_instruction_groups(groups: &[PhotonInstructionGroup]) -> Vec<RingsInstructionGroup> {
    let to_rings_instruction = |instruction: &PhotonInstruction| {
        RingsInstruction::new(
            instruction.program_id,
            instruction.accounts.clone(),
            instruction.data.clone(),
            instruction.stack_height,
        )
    };

    groups
        .iter()
        .map(|group| RingsInstructionGroup {
            outer: to_rings_instruction(&group.outer_instruction),
            inner: group
                .inner_instructions
                .iter()
                .map(to_rings_instruction)
                .collect(),
        })
        .collect()
}

fn find_event_sites(
    groups: &[RingsInstructionGroup],
    rings_program_id: Pubkey,
) -> Result<Vec<EventSite>, IngesterError> {
    let mut sites = Vec::new();

    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if !is_emit_event(rings_program_id, instruction) {
                continue;
            }

            let Some(parent) = event_parent(group, index)? else {
                continue;
            };

            if !is_event_source(rings_program_id, parent) {
                continue;
            }

            let source_instruction_tag = parent.data.first().copied().ok_or_else(|| {
                IngesterError::ParserError(
                    "Rings event parent instruction is missing source tag".to_string(),
                )
            })?;

            sites.push(EventSite {
                source_instruction_tag,
                payload: instruction.data.get(1..).unwrap_or_default().to_vec(),
            });
        }
    }

    Ok(sites)
}

fn event_parent(
    group: &RingsInstructionGroup,
    event_index: usize,
) -> Result<Option<&RingsInstruction>, IngesterError> {
    let event_instruction = group.inner.get(event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Rings event index {} is out of bounds for {} inner instructions",
            event_index,
            group.inner.len()
        ))
    })?;
    let Some(event_height) = event_instruction.stack_height else {
        return Ok(None);
    };
    let Some(parent_height) = event_height.checked_sub(1) else {
        return Ok(None);
    };
    let previous_instructions = group.inner.get(..event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Rings event parent search index {} is out of bounds for {} inner instructions",
            event_index,
            group.inner.len()
        ))
    })?;

    Ok(previous_instructions
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| (group.outer.stack_height == Some(parent_height)).then_some(&group.outer)))
}

fn is_event_source(rings_program_id: Pubkey, instruction: &RingsInstruction) -> bool {
    // Keep this in sync with shielded-pool processors that call
    // `emit_general_event`, directly or via process_transact_core /
    // process_merge_core. Self-emitting instructions: TRANSACT, ZONE_TRANSACT,
    // ZONE_AUTHORITY_TRANSACT (transact core); MERGE_TRANSACT, ZONE_MERGE_TRANSACT
    // (merge core); DEPOSIT, ZONE_DEPOSIT (deposit). Missing a tag here silently
    // drops those transactions from the index (they never get a rings_transactions
    // row).
    instruction.program_id == rings_program_id
        && matches!(
            instruction.data.first().copied(),
            Some(
                tag::TRANSACT
                    | tag::ZONE_TRANSACT
                    | tag::ZONE_AUTHORITY_TRANSACT
                    | tag::MERGE_TRANSACT
                    | tag::ZONE_MERGE_TRANSACT
                    | tag::DEPOSIT
                    | tag::ZONE_DEPOSIT
            )
        )
}

fn is_emit_event(rings_program_id: Pubkey, instruction: &RingsInstruction) -> bool {
    instruction.program_id == rings_program_id && instruction.data.first() == Some(&tag::EMIT_EVENT)
}
