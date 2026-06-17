use litesvm::types::TransactionMetadata;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use zolana_interface::event::{
    indexed_events_from_instruction_groups, proofless_output, EventDecodeError, EventKind,
    GeneralEvent, ProoflessShieldView,
};
pub use zolana_interface::event::{IndexedEvent, InstructionGroup, ParsedInstruction};

use crate::{ProgramTestError, TestIndexer};

pub fn parsed_instruction_from_compiled(
    account_keys: &[Pubkey],
    instruction: &CompiledInstruction,
    stack_height: Option<u32>,
) -> Result<ParsedInstruction, ProgramTestError> {
    let program_id = account_keys
        .get(instruction.program_id_index as usize)
        .copied()
        .ok_or_else(|| {
            ProgramTestError::Event(format!(
                "program id index {} out of bounds for {} account keys",
                instruction.program_id_index,
                account_keys.len()
            ))
        })?;
    let accounts = instruction
        .accounts
        .iter()
        .map(|index| {
            account_keys.get(*index as usize).copied().ok_or_else(|| {
                ProgramTestError::Event(format!(
                    "account index {index} out of bounds for {} account keys",
                    account_keys.len()
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedInstruction::new(
        program_id,
        accounts,
        instruction.data.clone(),
        stack_height,
    ))
}

pub fn parsed_instruction_groups_from_meta(
    account_keys: &[Pubkey],
    outer_instructions: &[CompiledInstruction],
    meta: &TransactionMetadata,
) -> Result<Vec<InstructionGroup>, ProgramTestError> {
    let mut groups = outer_instructions
        .iter()
        .map(|instruction| {
            parsed_instruction_from_compiled(account_keys, instruction, Some(1)).map(|outer| {
                InstructionGroup {
                    outer,
                    inner: Vec::new(),
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (outer_index, inner_instructions) in meta.inner_instructions.iter().enumerate() {
        let Some(group) = groups.get_mut(outer_index) else {
            return Err(ProgramTestError::Event(format!(
                "inner instruction group {outer_index} has no outer instruction"
            )));
        };
        group.inner = inner_instructions
            .iter()
            .map(|inner| {
                parsed_instruction_from_compiled(
                    account_keys,
                    &inner.instruction,
                    Some(u32::from(inner.stack_height)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
    }

    Ok(groups)
}

pub fn indexed_events_from_meta(
    shielded_pool_program_id: Pubkey,
    account_keys: &[Pubkey],
    outer_instructions: &[CompiledInstruction],
    meta: &TransactionMetadata,
) -> Result<Vec<IndexedEvent>, ProgramTestError> {
    let groups = parsed_instruction_groups_from_meta(account_keys, outer_instructions, meta)?;
    Ok(indexed_events_from_instruction_groups(
        shielded_pool_program_id,
        &groups,
    ))
}

pub fn index_events(
    indexer: &mut TestIndexer,
    events: &[IndexedEvent],
) -> Result<(), ProgramTestError> {
    for event in events {
        let (kind, general_event) = decoded_event(event)?;
        match kind {
            EventKind::ProoflessShield => {
                let view = proofless_output(general_event)
                    .map_err(|err| invalid_proofless_output(event, err))?;
                indexer.record_proofless_shield(&view)?;
            }
            EventKind::Transact => {
                indexer.record_transact(general_event)?;
            }
        }
    }
    Ok(())
}

pub fn single_proofless_shield_view(
    events: &[IndexedEvent],
) -> Result<ProoflessShieldView, ProgramTestError> {
    let mut proofless_views = events.iter().filter_map(|event| {
        let (kind, general_event) = match decoded_event(event) {
            Ok(decoded) => decoded,
            Err(err) => return Some(Err(err)),
        };
        match kind {
            EventKind::ProoflessShield => Some(
                proofless_output(general_event).map_err(|err| invalid_proofless_output(event, err)),
            ),
            EventKind::Transact => None,
        }
    });
    let Some(event) = proofless_views.next() else {
        return Err(ProgramTestError::Event(
            "no proofless shield event emitted by transaction".into(),
        ));
    };
    let event = event?;
    if proofless_views.next().transpose()?.is_some() {
        return Err(ProgramTestError::Event(
            "expected one proofless shield view".into(),
        ));
    }
    Ok(event)
}

fn decoded_event(event: &IndexedEvent) -> Result<(EventKind, &GeneralEvent), ProgramTestError> {
    let kind = event_kind(event)?;
    let general_event = event
        .decoded
        .as_ref()
        .map_err(|err| invalid_event(event, *err))?;
    Ok((kind, general_event))
}

fn event_kind(event: &IndexedEvent) -> Result<EventKind, ProgramTestError> {
    let Some(&kind) = event.payload.first() else {
        return Err(invalid_event(event, EventDecodeError::InvalidPayload));
    };
    EventKind::from_byte(kind)
        .ok_or_else(|| invalid_event(event, EventDecodeError::InvalidEventKind(kind)))
}

fn invalid_event(event: &IndexedEvent, err: EventDecodeError) -> ProgramTestError {
    ProgramTestError::Event(format!(
        "invalid shielded-pool event tag={} payload_len={} error={err:?}",
        event.tag,
        event.payload.len()
    ))
}

fn invalid_proofless_output(event: &IndexedEvent, err: EventDecodeError) -> ProgramTestError {
    ProgramTestError::Event(format!(
        "invalid proofless output tag={} payload_len={} error={err:?}",
        event.tag,
        event.payload.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::{
        event::{encode_event_payload, OutputUtxo},
        instruction::tag,
    };

    #[test]
    fn transact_events_update_indexer_but_not_proofless_views() {
        let event = transact_event([1u8; 32], [2u8; 32]);
        let mut indexer = TestIndexer::new();

        index_events(&mut indexer, std::slice::from_ref(&event)).expect("index event");
        let err = single_proofless_shield_view(&[event]).expect_err("proofless view");

        assert_eq!(indexer.utxos().len(), 2);
        assert_eq!(indexer.utxos()[0].utxo_hash, [1u8; 32]);
        assert_eq!(indexer.utxos()[1].utxo_hash, [2u8; 32]);
        assert!(err
            .to_string()
            .contains("no proofless shield event emitted by transaction"));
    }

    fn transact_event(first: [u8; 32], second: [u8; 32]) -> IndexedEvent {
        let event = GeneralEvent {
            inputs: Vec::new(),
            outputs: vec![output(first), output(second)],
            tx_viewing_pk: [0u8; 33],
            first_output_leaf_index: 0,
            output_tree: [0u8; 32],
            relay_fee: None,
            deposit_withdraw: None,
        };
        IndexedEvent {
            tag: tag::EMIT_EVENT,
            payload: encode_event_payload(EventKind::Transact, &event),
            decoded: Ok(event),
        }
    }

    fn output(utxo_hash: [u8; 32]) -> OutputUtxo {
        OutputUtxo {
            view_tag: [0u8; 32],
            utxo_hash,
            data: Vec::new(),
        }
    }
}
