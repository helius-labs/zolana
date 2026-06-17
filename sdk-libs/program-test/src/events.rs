use litesvm::types::TransactionMetadata;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use zolana_interface::event::{
    indexed_events_from_instruction_groups, proofless_output, DepositView,
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
        match &event.decoded {
            Ok(general_event) => {
                let event = proofless_output(general_event).map_err(|err| {
                    ProgramTestError::Event(format!(
                        "invalid proofless output tag={} payload_len={} error={err:?}",
                        event.tag,
                        event.payload.len()
                    ))
                })?;
                indexer.record_deposit(&event)?;
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

pub fn single_deposit_view(events: &[IndexedEvent]) -> Result<DepositView, ProgramTestError> {
    let mut proofless_views = events.iter().map(|event| match &event.decoded {
        Ok(general_event) => proofless_output(general_event).map_err(|err| {
            ProgramTestError::Event(format!(
                "invalid proofless output tag={} payload_len={} error={err:?}",
                event.tag,
                event.payload.len()
            ))
        }),
        Err(err) => Err(ProgramTestError::Event(format!(
            "invalid shielded-pool event tag={} payload_len={} error={err:?}",
            event.tag,
            event.payload.len()
        ))),
    });
    let Some(event) = proofless_views.next() else {
        return Err(ProgramTestError::Event(
            "no proofless deposit event emitted by transaction".into(),
        ));
    };
    let event = event?;
    if proofless_views.next().transpose()?.is_some() {
        return Err(ProgramTestError::Event(
            "expected one proofless deposit view".into(),
        ));
    }
    Ok(event)
}
