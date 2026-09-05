use super::event_site::{find_event_sites, to_rings_instruction_groups};
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::{NullifierTreeBatchUpdate, StateUpdate};
use crate::ingester::typedefs::block_info::TransactionInfo;
use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;
use zolana_event::EventKind;
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
    let event_sites = find_event_sites(&groups, pda::shielded_pool_program_id(), |source| {
        source == tag::BATCH_UPDATE_NULLIFIER_TREE
    })?;
    if event_sites.is_empty() {
        return Ok(None);
    }

    let mut state_update = StateUpdate::new();

    for event_site in &event_sites {
        let event = decode_nullifier_tree_update(&event_site.payload, tx)?;

        // `start_sequence_number` is the sequence number after the cascade's
        // first applied batch, and each further batch advances it by one.
        let sequence_number = event
            .start_sequence_number
            .checked_add(u64::from(event.num_update - 1))
            .ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Nullifier-tree update sequence number overflow in {}",
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

/// Decode the payload (`[kind, borsh(body)]`) of an authenticated
/// `BATCH_UPDATE_NULLIFIER_TREE` event site. Once a site has that parent, an
/// empty, mismatched or malformed envelope is a protocol error, not "no event".
fn decode_nullifier_tree_update(
    payload: &[u8],
    tx: &TransactionInfo,
) -> Result<NullifierTreeUpdateEvent, IngesterError> {
    let (kind, body) = payload.split_first().ok_or_else(|| {
        IngesterError::ParserError(format!(
            "NullifierTreeUpdateEvent in {} is missing its event kind",
            tx.signature
        ))
    })?;
    if EventKind::from_byte(*kind) != Some(EventKind::NullifierTreeUpdate) {
        return Err(IngesterError::ParserError(format!(
            "NullifierTreeUpdateEvent in {} has unexpected event kind {}",
            tx.signature, kind
        )));
    }

    NullifierTreeUpdateEvent::try_from_slice(body)
        .map_err(|err| {
            IngesterError::ParserError(format!(
                "Failed to decode NullifierTreeUpdateEvent in {}: {}",
                tx.signature, err
            ))
        })
        .and_then(|event| {
            if event.num_update == 0 {
                Err(IngesterError::ParserError(format!(
                    "NullifierTreeUpdateEvent in {} has zero applied updates",
                    tx.signature
                )))
            } else {
                Ok(event)
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::typedefs::block_info::{Instruction, InstructionGroup};
    use solana_signature::Signature;
    use zolana_event::encode_nullifier_tree_update_event;
    use zolana_interface::instruction::tag as event_tag;

    fn tree() -> Pubkey {
        Pubkey::new_from_array([7; 32])
    }

    fn event(num_update: u32) -> NullifierTreeUpdateEvent {
        NullifierTreeUpdateEvent {
            merkle_tree_pubkey: tree().to_bytes(),
            zkp_batch_size: 250,
            old_next_index: 500,
            start_sequence_number: 3,
            first_root_index: 4,
            num_update,
            first_zkp_batch_index: 2,
            new_root: [9; 32],
        }
    }

    fn instruction(program_id: Pubkey, data: Vec<u8>, stack_height: u32) -> Instruction {
        Instruction {
            program_id,
            accounts: vec![],
            data,
            stack_height: Some(stack_height),
        }
    }

    fn tx_emitting(event: &NullifierTreeUpdateEvent) -> TransactionInfo {
        let outer = instruction(
            pda::shielded_pool_program_id(),
            vec![tag::BATCH_UPDATE_NULLIFIER_TREE, 1, 2, 3],
            1,
        );
        let emit = instruction(
            pda::shielded_pool_program_id(),
            encode_nullifier_tree_update_event(event),
            2,
        );
        TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: outer,
                inner_instructions: vec![emit],
            }],
            signature: Signature::from([8; 64]),
            error: None,
        }
    }

    #[test]
    fn parses_single_batch_event() {
        let tx = tx_emitting(&event(1));

        let state_update = parse_nullifier_tree_batch_updates(&tx).unwrap().unwrap();

        assert_eq!(state_update.nullifier_tree_batch_updates.len(), 1);
        let update = state_update
            .nullifier_tree_batch_updates
            .first()
            .expect("one update");
        assert_eq!(update.tree, tree());
        assert_eq!(update.new_root, [9; 32]);
        assert_eq!(update.zkp_batch_size, 250);
        assert_eq!(update.num_update, 1);
        assert_eq!(update.appended_count(), 250);
        assert_eq!(update.signature, tx.signature);
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    #[test]
    fn parses_cascade_of_three_batches() {
        // The instruction that triggers a cascade looks no different; only the
        // event says three batches landed under it.
        let tx = tx_emitting(&event(3));

        let state_update = parse_nullifier_tree_batch_updates(&tx).unwrap().unwrap();

        let update = state_update
            .nullifier_tree_batch_updates
            .first()
            .expect("one update");
        assert_eq!(update.num_update, 3);
        assert_eq!(update.appended_count(), 750);
    }

    #[test]
    fn cascade_sequence_number_counts_batches_not_events() {
        // The tree's sequence number advances once per applied zkp batch, and
        // the root index a client quotes is derived from it. Taking
        // start_sequence_number alone would leave photon short by one per extra
        // batch, pointing clients at the wrong slot of the root history.
        let single = tx_emitting(&event(1));
        let cascade = tx_emitting(&event(3));

        let seq = |tx: &TransactionInfo| {
            parse_nullifier_tree_batch_updates(tx)
                .unwrap()
                .unwrap()
                .nullifier_tree_batch_updates
                .first()
                .expect("one update")
                .sequence_number
        };

        // start_sequence_number is 3 in the fixture: the number after the first
        // applied batch.
        assert_eq!(seq(&single), 3);
        assert_eq!(seq(&cascade), 5);
    }

    #[test]
    fn ignores_instruction_that_emitted_no_event() {
        // A proof cached out of order applies nothing and emits nothing. Reading
        // the instruction instead would record a root the tree never took.
        let tx = TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: instruction(
                    pda::shielded_pool_program_id(),
                    vec![tag::BATCH_UPDATE_NULLIFIER_TREE, 1, 2, 3],
                    1,
                ),
                inner_instructions: vec![],
            }],
            signature: Signature::from([8; 64]),
            error: None,
        };

        assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
        assert!(has_nullifier_tree_batch_update(&tx));
    }

    #[test]
    fn ignores_general_event_under_a_transact() {
        let tx = TransactionInfo {
            instruction_groups: vec![InstructionGroup {
                outer_instruction: instruction(
                    pda::shielded_pool_program_id(),
                    vec![tag::TRANSACT],
                    1,
                ),
                inner_instructions: vec![instruction(
                    pda::shielded_pool_program_id(),
                    vec![event_tag::EMIT_EVENT, EventKind::Transact as u8],
                    2,
                )],
            }],
            signature: Signature::from([8; 64]),
            error: None,
        };

        assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
        assert!(!has_nullifier_tree_batch_update(&tx));
    }

    #[test]
    fn ignores_event_forged_by_a_foreign_parent() {
        let mut tx = tx_emitting(&event(1));
        let group = tx.instruction_groups.first_mut().expect("one group");
        group.outer_instruction.program_id = Pubkey::new_from_array([9; 32]);

        assert!(parse_nullifier_tree_batch_updates(&tx).unwrap().is_none());
    }

    #[test]
    fn rejects_an_authenticated_event_with_a_missing_or_wrong_kind() {
        let tx = tx_emitting(&event(1));

        assert!(decode_nullifier_tree_update(&[], &tx).is_err());
        assert!(decode_nullifier_tree_update(&[EventKind::Transact as u8], &tx).is_err());
    }

    #[test]
    fn rejects_an_event_that_claims_zero_applied_updates() {
        let tx = tx_emitting(&event(0));

        assert!(parse_nullifier_tree_batch_updates(&tx).is_err());
    }
}
