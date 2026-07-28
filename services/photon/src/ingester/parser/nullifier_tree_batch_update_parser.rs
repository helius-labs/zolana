use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::{NullifierTreeBatchUpdate, StateUpdate};
use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo};
use borsh::BorshDeserialize;
use cadence_macros::statsd_count;
use solana_pubkey::Pubkey;
use zolana_batched_merkle_tree::events::BatchAddressAppendEvent;
use zolana_event::{tag as event_tag, EventKind};
use zolana_interface::{instruction::tag, pda};

/// Extract applied nullifier-tree batch updates from the transaction's emitted
/// `BatchAddressAppendEvent`s, never from instruction data.
///
/// The shielded-pool program emits the event (via an `EMIT_EVENT` self-CPI)
/// only when a batch update was actually applied to the tree
/// (`process_batch_update_nullifier_tree` emits nothing when the update is a
/// no-op), so the event is the ground truth for "an update happened" and for
/// the resulting root. Instruction data only expresses intent: a forged CPI
/// with tag 51 fails the on-chain forester-authority check but still leaves a
/// successful transaction behind, and a genuine update can succeed without
/// applying anything -- both used to be ingested as applied updates and then
/// aborted the block at persist time (F-04).
///
/// Authentication mirrors `rings_event_parser`: an `EMIT_EVENT` inner
/// instruction is only trusted when its direct parent (reconstructed via
/// `stack_height`) is a shielded-pool instruction with tag
/// `BATCH_UPDATE_NULLIFIER_TREE`. An attacker cannot fabricate that shape:
/// the failed tag-51 CPI emits no event, and a direct `EMIT_EVENT` CPI is
/// parented to the attacker's own instruction.
pub fn parse_nullifier_tree_batch_update(
    tx: &TransactionInfo,
) -> Result<Option<StateUpdate>, IngesterError> {
    if tx.error.is_some() {
        return Ok(None);
    }

    let mut state_update = StateUpdate::new();

    for group in &tx.instruction_groups {
        for (index, instruction) in group.inner_instructions.iter().enumerate() {
            if !is_emit_event(instruction) {
                continue;
            }

            let Some(parent) = event_parent(group, index)? else {
                continue;
            };
            if !is_batch_update_source(parent) {
                log::debug!(
                    "Dropping BatchAddressAppend event with foreign parent {} in {}",
                    parent.program_id,
                    tx.signature
                );
                continue;
            }

            let payload = instruction.data.get(1..).unwrap_or_default();
            let Some((&kind_byte, event_bytes)) = payload.split_first() else {
                continue;
            };
            if EventKind::from_byte(kind_byte) != Some(EventKind::BatchAddressAppend) {
                continue;
            }

            let event = BatchAddressAppendEvent::try_from_slice(event_bytes).map_err(|err| {
                statsd_count!("batch_event_decode_failures", 1);
                IngesterError::ParserError(format!(
                    "Failed to decode BatchAddressAppendEvent for {}: {}",
                    tx.signature, err
                ))
            })?;

            state_update
                .nullifier_tree_batch_updates
                .push(NullifierTreeBatchUpdate {
                    tree: Pubkey::from(event.merkle_tree_pubkey),
                    new_root: event.new_root,
                    signature: tx.signature,
                });
        }
    }

    if state_update == StateUpdate::default() {
        return Ok(None);
    }
    Ok(Some(state_update))
}

/// Reconstruct the direct parent of the event instruction at `event_index`
/// from stack heights: the closest preceding inner instruction one level up,
/// or the outer instruction when the event is a direct child of it.
fn event_parent(
    group: &InstructionGroup,
    event_index: usize,
) -> Result<Option<&Instruction>, IngesterError> {
    let event_instruction = group.inner_instructions.get(event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Batch event index {} is out of bounds for {} inner instructions",
            event_index,
            group.inner_instructions.len()
        ))
    })?;
    let Some(event_height) = event_instruction.stack_height else {
        log::debug!("Dropping batch event instruction with no stack_height");
        return Ok(None);
    };
    let Some(parent_height) = event_height.checked_sub(1) else {
        return Ok(None);
    };

    let previous_instructions = group.inner_instructions.get(..event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Batch event parent search index {} is out of bounds for {} inner instructions",
            event_index,
            group.inner_instructions.len()
        ))
    })?;

    Ok(previous_instructions
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| {
            (group.outer_instruction.stack_height == Some(parent_height))
                .then_some(&group.outer_instruction)
        }))
}

/// The event is only genuine when emitted from inside a shielded-pool
/// `BATCH_UPDATE_NULLIFIER_TREE` execution.
fn is_batch_update_source(instruction: &Instruction) -> bool {
    instruction.program_id == pda::shielded_pool_program_id()
        && instruction.data.first() == Some(&tag::BATCH_UPDATE_NULLIFIER_TREE)
}

fn is_emit_event(instruction: &Instruction) -> bool {
    instruction.program_id == pda::shielded_pool_program_id()
        && instruction.data.first() == Some(&event_tag::EMIT_EVENT)
}

/// Conservative snapshot pre-filter: keeps any transaction containing a
/// batch-update instruction. Deliberately instruction-data based (a superset
/// of what `parse_nullifier_tree_batch_update` records) so snapshots never
/// drop a transaction that might carry an applied update; it has no state
/// impact.
pub fn has_nullifier_tree_batch_update(tx: &TransactionInfo) -> bool {
    if tx.error.is_some() {
        return false;
    }

    tx.instruction_groups.iter().any(|instruction_group| {
        std::iter::once(&instruction_group.outer_instruction)
            .chain(instruction_group.inner_instructions.iter())
            .any(is_nullifier_tree_batch_update)
    })
}

fn is_nullifier_tree_batch_update(instruction: &Instruction) -> bool {
    instruction.program_id == pda::shielded_pool_program_id()
        && instruction.data.first() == Some(&tag::BATCH_UPDATE_NULLIFIER_TREE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::typedefs::block_info::InstructionGroup;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use zolana_event::encode_event_instruction_with;
    use zolana_interface::instruction::{
        encode_instruction, BatchUpdateNullifierTreeData, CompressedProof,
    };

    fn batch_update_data(new_root: [u8; 32]) -> BatchUpdateNullifierTreeData {
        BatchUpdateNullifierTreeData {
            new_root,
            old_root: [8; 32],
            zkp_batch_index: 0,
            compressed_proof: CompressedProof {
                a: [1; 32],
                b: [2; 64],
                c: [3; 32],
            },
        }
    }

    fn batch_update_instruction(
        tree: Pubkey,
        new_root: [u8; 32],
        stack_height: u32,
    ) -> Instruction {
        Instruction {
            program_id: pda::shielded_pool_program_id(),
            accounts: vec![
                Pubkey::new_from_array([4; 32]),
                pda::protocol_config(),
                tree,
            ],
            data: encode_instruction(
                tag::BATCH_UPDATE_NULLIFIER_TREE,
                &batch_update_data(new_root),
            ),
            stack_height: Some(stack_height),
        }
    }

    fn tx_with_group(group: InstructionGroup) -> TransactionInfo {
        TransactionInfo {
            instruction_groups: vec![group],
            signature: Signature::from([8; 64]),
            error: None,
        }
    }

    fn batch_append_event(tree: Pubkey, new_root: [u8; 32]) -> BatchAddressAppendEvent {
        BatchAddressAppendEvent {
            merkle_tree_pubkey: tree.to_bytes(),
            zkp_batch_size: 250,
            old_next_index: 2,
            start_sequence_number: 1,
            first_root_index: 3,
            num_update: 1,
            first_zkp_batch_index: 0,
            new_root,
        }
    }

    fn batch_append_event_instruction(
        event: &BatchAddressAppendEvent,
        stack_height: u32,
    ) -> Instruction {
        Instruction {
            program_id: pda::shielded_pool_program_id(),
            accounts: vec![],
            data: encode_event_instruction_with(EventKind::BatchAddressAppend, event),
            stack_height: Some(stack_height),
        }
    }

    /// Positive control: a genuine batch update whose event was emitted. Must
    /// record exactly one update with the event's tree and final root.
    #[test]
    fn parses_batch_update_from_emitted_event() {
        let tree = Pubkey::new_from_array([7; 32]);
        let new_root = [9; 32];
        let event = batch_append_event(tree, new_root);
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: batch_update_instruction(tree, new_root, 1),
            inner_instructions: vec![batch_append_event_instruction(&event, 2)],
        });

        let state_update = parse_nullifier_tree_batch_update(&tx).unwrap().unwrap();

        assert_eq!(state_update.nullifier_tree_batch_updates.len(), 1);
        assert_eq!(state_update.nullifier_tree_batch_updates[0].tree, tree);
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].new_root,
            new_root
        );
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].signature,
            tx.signature
        );
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    /// The tree and root come from the event, not the instruction data: a
    /// cascade event whose final root differs from the (stale) instruction
    /// `new_root` is recorded with the event values.
    #[test]
    fn records_event_root_not_instruction_root() {
        let tree = Pubkey::new_from_array([7; 32]);
        let event = batch_append_event(tree, [42; 32]);
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: batch_update_instruction(tree, [9; 32], 1),
            inner_instructions: vec![batch_append_event_instruction(&event, 2)],
        });

        let state_update = parse_nullifier_tree_batch_update(&tx).unwrap().unwrap();

        assert_eq!(state_update.nullifier_tree_batch_updates.len(), 1);
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].new_root,
            [42; 32]
        );
    }

    /// A forged `EMIT_EVENT` CPI whose parent is an attacker program is not
    /// authenticated and must be dropped.
    #[test]
    fn drops_event_with_foreign_parent() {
        let attacker = Pubkey::new_from_array([6; 32]);
        let event = batch_append_event(Pubkey::new_from_array([7; 32]), [66; 32]);
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: Instruction {
                program_id: attacker,
                accounts: vec![],
                data: vec![0],
                stack_height: Some(1),
            },
            inner_instructions: vec![batch_append_event_instruction(&event, 2)],
        });

        assert!(parse_nullifier_tree_batch_update(&tx).unwrap().is_none());
    }

    /// A batch-append event parented to a different shielded-pool instruction
    /// (e.g. TRANSACT) is not a nullifier-tree batch update.
    #[test]
    fn drops_event_under_non_batch_update_parent() {
        let event = batch_append_event(Pubkey::new_from_array([7; 32]), [66; 32]);
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: Instruction {
                program_id: pda::shielded_pool_program_id(),
                accounts: vec![],
                data: vec![tag::TRANSACT],
                stack_height: Some(1),
            },
            inner_instructions: vec![batch_append_event_instruction(&event, 2)],
        });

        assert!(parse_nullifier_tree_batch_update(&tx).unwrap().is_none());
    }

    #[test]
    fn ignores_transaction_without_batch_update() {
        let tx = TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: Instruction {
                    program_id: pda::shielded_pool_program_id(),
                    accounts: vec![],
                    data: vec![tag::TRANSACT],
                    stack_height: Some(1),
                },
                inner_instructions: vec![],
            }],
            signature: Signature::from([8; 64]),
            error: None,
        };

        assert!(parse_nullifier_tree_batch_update(&tx).unwrap().is_none());
        assert!(!has_nullifier_tree_batch_update(&tx));
    }

    /// F-04 attack vector A: an attacker program CPIs the shielded pool with
    /// tag 51 and a forged `new_root`. On chain the forester-authority check
    /// rejects the update and the attacker swallows the error, so the
    /// transaction succeeds with no `BatchAddressAppendEvent`. The parser must
    /// record nothing.
    #[test]
    fn drops_forged_batch_update_cpi_without_event() {
        let attacker = Pubkey::new_from_array([6; 32]);
        let forged_root = [66; 32];
        let forged_cpi = batch_update_instruction(Pubkey::new_from_array([7; 32]), forged_root, 2);
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: Instruction {
                program_id: attacker,
                accounts: vec![],
                data: vec![0],
                stack_height: Some(1),
            },
            inner_instructions: vec![forged_cpi],
        });

        assert!(parse_nullifier_tree_batch_update(&tx).unwrap().is_none());
    }

    /// F-04 failure vector B: a genuine forester batch update that succeeds
    /// without applying anything (`update_tree_from_address_queue` returns
    /// `Ok(None)` for a replayed/cached proof), so no event is emitted. The
    /// parser must record nothing.
    #[test]
    fn drops_successful_batch_update_without_event() {
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: batch_update_instruction(
                Pubkey::new_from_array([7; 32]),
                [9; 32],
                1,
            ),
            inner_instructions: vec![],
        });

        assert!(parse_nullifier_tree_batch_update(&tx).unwrap().is_none());
    }

    /// Forester-via-zone-program wrapper shape: the tag-51 batch update runs
    /// as a CPI inside an outer zone-program instruction, so its event sits at
    /// height 3. Parent reconstruction must walk to the height-2 tag-51
    /// instruction and record the update.
    #[test]
    fn parses_zone_rail_event_nested_at_height_three() {
        let zone_program = Pubkey::new_from_array([6; 32]);
        let tree = Pubkey::new_from_array([7; 32]);
        let new_root = [9; 32];
        let event = batch_append_event(tree, new_root);
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: Instruction {
                program_id: zone_program,
                accounts: vec![],
                data: vec![0],
                stack_height: Some(1),
            },
            inner_instructions: vec![
                batch_update_instruction(tree, new_root, 2),
                batch_append_event_instruction(&event, 3),
            ],
        });

        let state_update = parse_nullifier_tree_batch_update(&tx).unwrap().unwrap();

        assert_eq!(state_update.nullifier_tree_batch_updates.len(), 1);
        assert_eq!(state_update.nullifier_tree_batch_updates[0].tree, tree);
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].new_root,
            new_root
        );
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    /// Two authenticated batch-append events (different trees and roots) under
    /// valid tag-51 parents in one transaction: both recorded, in order.
    #[test]
    fn records_multiple_events_in_order() {
        let tree_a = Pubkey::new_from_array([7; 32]);
        let tree_b = Pubkey::new_from_array([5; 32]);
        let root_a = [9; 32];
        let root_b = [4; 32];
        let event_a = batch_append_event(tree_a, root_a);
        let event_b = batch_append_event(tree_b, root_b);
        let tx = TransactionInfo {
            instruction_groups: vec![
                InstructionGroup {
                    outer_instruction: batch_update_instruction(tree_a, root_a, 1),
                    inner_instructions: vec![batch_append_event_instruction(&event_a, 2)],
                },
                InstructionGroup {
                    outer_instruction: batch_update_instruction(tree_b, root_b, 1),
                    inner_instructions: vec![batch_append_event_instruction(&event_b, 2)],
                },
            ],
            signature: Signature::from([8; 64]),
            error: None,
        };

        let state_update = parse_nullifier_tree_batch_update(&tx).unwrap().unwrap();

        assert_eq!(state_update.nullifier_tree_batch_updates.len(), 2);
        assert_eq!(state_update.nullifier_tree_batch_updates[0].tree, tree_a);
        assert_eq!(
            state_update.nullifier_tree_batch_updates[0].new_root,
            root_a
        );
        assert_eq!(state_update.nullifier_tree_batch_updates[1].tree, tree_b);
        assert_eq!(
            state_update.nullifier_tree_batch_updates[1].new_root,
            root_b
        );
    }

    /// An event instruction without a stack height cannot be authenticated
    /// (no parent can be reconstructed) and must be dropped.
    #[test]
    fn drops_event_without_stack_height() {
        let tree = Pubkey::new_from_array([7; 32]);
        let new_root = [9; 32];
        let event = batch_append_event(tree, new_root);
        let mut event_instruction = batch_append_event_instruction(&event, 2);
        event_instruction.stack_height = None;
        let tx = tx_with_group(InstructionGroup {
            outer_instruction: batch_update_instruction(tree, new_root, 1),
            inner_instructions: vec![event_instruction],
        });

        assert!(parse_nullifier_tree_batch_update(&tx).unwrap().is_none());
    }
}
