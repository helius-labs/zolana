use super::event_site::{find_event_sites, to_instruction_groups};
use super::state_update::{
    RingsMessageUpdate, RingsNullifierUpdate, RingsOutputUpdate, RingsTransactionUpdate,
    StateUpdate,
};
use crate::ingester::{error::IngesterError, typedefs::block_info::TransactionInfo};
use solana_pubkey::Pubkey;
use zolana_event::{decode_event_payload, tag, ParsedInstruction as RingsInstruction};
use zolana_interface::pda;

const RINGS_PARSE_VERSION: i16 = 3;

pub fn parse_rings_events(
    tx: &TransactionInfo,
    slot: u64,
) -> Result<Option<StateUpdate>, IngesterError> {
    let rings_program_id = pda::shielded_pool_program_id();
    let groups = to_instruction_groups(&tx.instruction_groups);
    let event_sites = find_event_sites(&groups, rings_program_id, is_emit_event, is_event_source)?;

    if event_sites.is_empty() {
        return Ok(None);
    }

    let mut state_update = StateUpdate::new();

    for (event_index, event_site) in event_sites.into_iter().enumerate() {
        let event_index_i16 = i16::try_from(event_index).map_err(|_| {
            IngesterError::ParserError(format!("Event index {} does not fit in i16", event_index))
        })?;
        // Bytes after the `EMIT_EVENT` tag, `[EventKind, borsh(GeneralEvent)]`.
        let payload = event_site.data.get(1..).unwrap_or_default().to_vec();
        let event = decode_event_payload(&payload).map_err(|err| {
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
                raw_event: Some(payload),
                parse_version: RINGS_PARSE_VERSION,
                outputs,
                messages,
                nullifiers,
            });
    }

    Ok(Some(state_update))
}

fn is_event_source(rings_program_id: Pubkey, instruction: &RingsInstruction) -> bool {
    // Keep in sync with the shielded-pool processors that call
    // `emit_general_event`, directly or via process_transact_core /
    // process_merge_core. MERGE_CHAIN_TRANSACT emits one event for the whole
    // chain and AGGREGATE_TRANSACT one per settled leg, numbered by `event_index`.
    // A tag missing here silently drops those transactions from the index.
    // `every_instruction_tag_is_classified` fails until a new tag is classified.
    instruction.program_id == rings_program_id
        && matches!(
            instruction.data.first().copied(),
            Some(
                tag::TRANSACT
                    | tag::RING_TRANSACT
                    | tag::RING_AUTHORITY_TRANSACT
                    | tag::MERGE_TRANSACT
                    | tag::RING_MERGE_TRANSACT
                    | tag::MERGE_CHAIN_TRANSACT
                    | tag::AGGREGATE_TRANSACT
                    | tag::DEPOSIT
                    | tag::RING_DEPOSIT
            )
        )
}

fn is_emit_event(rings_program_id: Pubkey, instruction: &RingsInstruction) -> bool {
    instruction.program_id == rings_program_id && instruction.data.first() == Some(&tag::EMIT_EVENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::event_site::EventSite;
    use zolana_event::tag::InstructionTag;
    use zolana_event::{InstructionGroup, ParsedInstruction};

    fn spp() -> Pubkey {
        pda::shielded_pool_program_id()
    }

    /// Stand-in for any foreign program (attacker contract, ring program).
    fn foreign() -> Pubkey {
        Pubkey::new_from_array([9; 32])
    }

    fn ix(program_id: Pubkey, tag_byte: u8, stack_height: u32) -> ParsedInstruction {
        ParsedInstruction::new(
            program_id,
            Vec::new(),
            vec![tag_byte, 1, 2, 3],
            Some(stack_height),
        )
    }

    fn event_sites(groups: &[InstructionGroup]) -> Vec<EventSite> {
        find_event_sites(groups, spp(), is_emit_event, is_event_source).unwrap()
    }

    #[test]
    fn accepts_genuine_self_emitted_event() {
        let groups = [InstructionGroup {
            outer: ix(spp(), tag::TRANSACT, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
        }];

        let sites = event_sites(&groups);

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].source_instruction_tag, tag::TRANSACT);
    }

    #[test]
    fn accepts_ring_rail_event_nested_at_height_three() {
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![
                ix(spp(), tag::RING_TRANSACT, 2),
                ix(spp(), tag::EMIT_EVENT, 3),
            ],
        }];

        let sites = event_sites(&groups);

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].source_instruction_tag, tag::RING_TRANSACT);
    }

    #[test]
    fn drops_event_forged_by_direct_foreign_cpi() {
        // Attacker program CPIs SPP with EMIT_EVENT. The event's parent is the
        // attacker's top-level instruction.
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
        }];

        assert!(event_sites(&groups).is_empty());
    }

    #[test]
    fn drops_event_forged_under_a_foreign_inner_parent() {
        // Attacker nests one level deeper so the forged event's stack height
        // matches the genuine ring-rail shape. The parent is still foreign.
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![ix(foreign(), 0, 2), ix(spp(), tag::EMIT_EVENT, 3)],
        }];

        assert!(event_sites(&groups).is_empty());
    }

    #[test]
    fn drops_event_parented_to_another_emit_event() {
        // A second EMIT_EVENT whose reconstructed parent is the first EMIT_EVENT.
        // The event-source whitelist never includes EMIT_EVENT.
        let groups = [InstructionGroup {
            outer: ix(spp(), tag::TRANSACT, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2), ix(spp(), tag::EMIT_EVENT, 3)],
        }];

        let sites = event_sites(&groups);

        assert_eq!(sites.len(), 1);
    }

    #[test]
    fn drops_event_without_stack_height() {
        let groups = [InstructionGroup {
            outer: ix(spp(), tag::TRANSACT, 1),
            inner: vec![ParsedInstruction::new(
                spp(),
                Vec::new(),
                vec![tag::EMIT_EVENT],
                None,
            )],
        }];

        assert!(event_sites(&groups).is_empty());
    }

    /// Every implemented instruction tag is either an event source or listed
    /// here as silent. A new tag matches neither and fails, which is the only
    /// thing standing between an emitting instruction and being dropped from
    /// the index.
    #[test]
    fn every_instruction_tag_is_classified() {
        // Processors that never call `emit_general_event` are configuration,
        // account creation, tree maintenance, and the event carrier itself.
        const SILENT: [u8; 12] = [
            tag::CREATE_PROTOCOL_CONFIG,
            tag::UPDATE_PROTOCOL_CONFIG,
            tag::CREATE_TREE,
            tag::PAUSE_TREE,
            tag::BATCH_UPDATE_NULLIFIER_TREE,
            tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED,
            tag::CREATE_ASSET_COUNTER,
            tag::CREATE_SPL_INTERFACE,
            tag::CREATE_RING_CONFIG,
            tag::UPDATE_RING_CONFIG,
            tag::UPDATE_RING_CONFIG_OWNER,
            tag::EMIT_EVENT,
        ];

        for byte in 0..=u8::MAX {
            if InstructionTag::try_from(byte).is_err() {
                continue;
            }
            let source = is_event_source(spp(), &ix(spp(), byte, 1));
            assert_ne!(
                source,
                SILENT.contains(&byte),
                "tag {byte} is neither an event source nor listed as silent"
            );
        }
    }

    /// The two tree-maintenance tags emit their own append event and settle no
    /// UTXOs, so they must not be mistaken for a settlement site.
    #[test]
    fn tree_maintenance_is_not_an_event_source() {
        for byte in [
            tag::BATCH_UPDATE_NULLIFIER_TREE,
            tag::BATCH_UPDATE_NULLIFIER_TREE_FOLDED,
        ] {
            assert!(!is_event_source(spp(), &ix(spp(), byte, 1)));
        }
    }

    /// Both recursive rails settle through `emit_general_event`, so a batch and
    /// a chained merge each get a row.
    #[test]
    fn recursive_rails_are_event_sources() {
        for byte in [tag::AGGREGATE_TRANSACT, tag::MERGE_CHAIN_TRANSACT] {
            assert!(is_event_source(spp(), &ix(spp(), byte, 1)));
        }
    }
}
