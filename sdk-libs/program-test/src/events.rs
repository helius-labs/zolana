use litesvm::types::TransactionMetadata;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use zolana_interface::{
    event::{decode_event_instruction, EventDecodeError, ProoflessShieldEvent, ShieldedPoolEvent},
    instruction::tag,
};

use crate::{ProgramTestError, TestIndexer};

#[derive(Clone, Debug)]
pub struct ParsedInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct IndexedEvent {
    pub tag: u8,
    pub payload: Vec<u8>,
    pub decoded: Result<ShieldedPoolEvent, EventDecodeError>,
}

pub fn parsed_instruction_from_compiled(
    account_keys: &[Pubkey],
    instruction: &CompiledInstruction,
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
    Ok(ParsedInstruction {
        program_id,
        accounts,
        data: instruction.data.clone(),
    })
}

pub fn indexed_events_from_meta(
    shielded_pool_program_id: Pubkey,
    account_keys: &[Pubkey],
    meta: &TransactionMetadata,
) -> Result<Vec<IndexedEvent>, ProgramTestError> {
    let instructions = meta
        .inner_instructions
        .iter()
        .flatten()
        .map(|inner| parsed_instruction_from_compiled(account_keys, &inner.instruction))
        .collect::<Result<Vec<_>, _>>()?;
    indexed_events_from_instructions(shielded_pool_program_id, &instructions)
}

pub fn indexed_events_from_instructions<'a>(
    shielded_pool_program_id: Pubkey,
    instructions: impl IntoIterator<Item = &'a ParsedInstruction>,
) -> Result<Vec<IndexedEvent>, ProgramTestError> {
    let mut events = Vec::new();
    for instruction in instructions {
        if instruction.program_id == shielded_pool_program_id
            && instruction.data.first() == Some(&tag::EMIT_EVENT)
        {
            events.push(parse_indexed_event(&instruction.data));
        }
    }
    Ok(events)
}

fn parse_indexed_event(data: &[u8]) -> IndexedEvent {
    let payload = data.get(1..).unwrap_or_default().to_vec();
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload,
        decoded: decode_event_instruction(data),
    }
}

pub fn index_events(
    indexer: &mut TestIndexer,
    events: &[IndexedEvent],
) -> Result<(), ProgramTestError> {
    for event in events {
        match &event.decoded {
            Ok(ShieldedPoolEvent::ProoflessShield(event)) => {
                indexer.record_proofless_shield(event)?;
            }
            Err(err) => {
                return Err(ProgramTestError::Event(format!(
                    "invalid shielded-pool event tag={} payload_len={} error={err:?}",
                    event.tag,
                    event.payload.len()
                )));
            }
        }
    }
    Ok(())
}

pub fn single_proofless_shield_event(
    events: &[IndexedEvent],
) -> Result<ProoflessShieldEvent, ProgramTestError> {
    let mut proofless_events = events.iter().map(|event| match &event.decoded {
        Ok(ShieldedPoolEvent::ProoflessShield(event)) => Ok(event),
        Err(err) => Err(ProgramTestError::Event(format!(
            "invalid shielded-pool event tag={} payload_len={} error={err:?}",
            event.tag,
            event.payload.len()
        ))),
    });
    let Some(event) = proofless_events.next() else {
        return Err(ProgramTestError::Event(
            "no proofless shield event emitted by transaction".into(),
        ));
    };
    let event = event?.clone();
    if proofless_events.next().transpose()?.is_some() {
        return Err(ProgramTestError::Event(
            "expected one proofless shield event".into(),
        ));
    }
    Ok(event)
}
