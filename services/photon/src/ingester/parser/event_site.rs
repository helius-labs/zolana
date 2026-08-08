//! Locate self-CPI event instructions in a transaction.
//!
//! `EMIT_EVENT` validates nothing on chain, so any caller can invoke it with
//! forged bytes. An event is trustworthy only when its reconstructed parent is
//! an instruction of the same program carrying a state-transitioning tag. Both
//! the Rings and the Squads zone logs need that walk, so it lives here once.

use solana_pubkey::Pubkey;
use zolana_event::{InstructionGroup, ParsedInstruction};

use crate::ingester::{
    error::IngesterError,
    typedefs::block_info::{
        Instruction as PhotonInstruction, InstructionGroup as PhotonInstructionGroup,
    },
};

pub(super) struct EventSite {
    pub source_instruction_tag: u8,
    /// Full `EMIT_EVENT` instruction data, leading tag byte included.
    pub data: Vec<u8>,
}

/// Program-scoped instruction test. Both the event carrier and the accepted
/// parent tags are program specific.
pub(super) type InstructionPredicate = fn(Pubkey, &ParsedInstruction) -> bool;

pub(super) fn to_instruction_groups(groups: &[PhotonInstructionGroup]) -> Vec<InstructionGroup> {
    let to_instruction = |instruction: &PhotonInstruction| {
        ParsedInstruction::new(
            instruction.program_id,
            instruction.accounts.clone(),
            instruction.data.clone(),
            instruction.stack_height,
        )
    };

    groups
        .iter()
        .map(|group| InstructionGroup {
            outer: to_instruction(&group.outer_instruction),
            inner: group
                .inner_instructions
                .iter()
                .map(to_instruction)
                .collect(),
        })
        .collect()
}

pub(super) fn find_event_sites(
    groups: &[InstructionGroup],
    program_id: Pubkey,
    is_emit_event: InstructionPredicate,
    is_event_source: InstructionPredicate,
) -> Result<Vec<EventSite>, IngesterError> {
    let mut sites = Vec::new();

    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if !is_emit_event(program_id, instruction) {
                continue;
            }

            let Some(parent) = event_parent(group, index)? else {
                continue;
            };

            if !is_event_source(program_id, parent) {
                continue;
            }

            let source_instruction_tag = parent.data.first().copied().ok_or_else(|| {
                IngesterError::ParserError(
                    "Event parent instruction is missing source tag".to_string(),
                )
            })?;

            sites.push(EventSite {
                source_instruction_tag,
                data: instruction.data.clone(),
            });
        }
    }

    Ok(sites)
}

fn event_parent(
    group: &InstructionGroup,
    event_index: usize,
) -> Result<Option<&ParsedInstruction>, IngesterError> {
    let event_instruction = group.inner.get(event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Event index {} is out of bounds for {} inner instructions",
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
            "Event parent search index {} is out of bounds for {} inner instructions",
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
