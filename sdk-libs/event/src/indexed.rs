use solana_pubkey::Pubkey;
use zolana_event::{tag, EventKind, GeneralEvent};

use crate::{
    instruction::{InstructionGroup, ParsedInstruction},
    reconstruct::reconstruct_general_event,
    EventDecodeError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEvent {
    /// SPP instruction tag: always [`tag::EMIT_EVENT`] for logged events.
    pub tag: u8,
    /// Bytes after `EMIT_EVENT`: `[EventKind, borsh(body)]`.
    pub payload: Vec<u8>,
    /// The `GeneralEvent` view, rebuilt from `payload` and the instruction that
    /// emitted it.
    pub decoded: Result<GeneralEvent, EventDecodeError>,
}

/// Returns the [`EventKind`] carried by an indexed `EMIT_EVENT` self-CPI payload
/// (`payload` is everything after the `EMIT_EVENT` tag byte). Do not read
/// [`IndexedEvent::tag`], which is always [`tag::EMIT_EVENT`].
pub fn event_kind_from_indexed(event: &IndexedEvent) -> Option<EventKind> {
    event
        .payload
        .first()
        .copied()
        .and_then(EventKind::from_byte)
}

/// Returns the reconstructed [`GeneralEvent`] when the indexed payload is valid.
pub fn general_event_from_indexed(event: &IndexedEvent) -> Result<&GeneralEvent, EventDecodeError> {
    match &event.decoded {
        Ok(general_event) => Ok(general_event),
        Err(err) => Err(*err),
    }
}

/// Every `EMIT_EVENT` self-CPI whose direct parent is a state-transitioning SPP
/// instruction, each rebuilt against that parent.
pub fn indexed_events_from_instruction_groups(
    shielded_pool_program_id: Pubkey,
    groups: &[InstructionGroup],
) -> Vec<IndexedEvent> {
    let mut events = Vec::new();
    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if !is_emit_event(shielded_pool_program_id, instruction) {
                continue;
            }
            if let Some(source) = event_source_parent(shielded_pool_program_id, group, index) {
                events.push(indexed_event(source, &instruction.data));
            }
        }
    }
    events
}

pub fn instruction_may_emit_events(
    shielded_pool_program_id: Pubkey,
    instruction: &ParsedInstruction,
) -> bool {
    is_event_source(shielded_pool_program_id, instruction)
        || is_ring_wrapper_event_source(shielded_pool_program_id, instruction)
}

fn indexed_event(source: &ParsedInstruction, data: &[u8]) -> IndexedEvent {
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: data.get(1..).unwrap_or_default().to_vec(),
        decoded: reconstruct_general_event(source, data),
    }
}

/// The instruction that invoked `group.inner[event_index]`: the nearest preceding
/// inner instruction one stack level up, else the outer instruction. `None`
/// unless that parent is an SPP event source.
fn event_source_parent(
    shielded_pool_program_id: Pubkey,
    group: &InstructionGroup,
    event_index: usize,
) -> Option<&ParsedInstruction> {
    let event_height = group.inner.get(event_index)?.stack_height?;
    let parent_height = event_height.checked_sub(1)?;
    let preceding = group.inner.get(..event_index)?;
    let parent = preceding
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| (group.outer.stack_height == Some(parent_height)).then_some(&group.outer))?;
    is_event_source(shielded_pool_program_id, parent).then_some(parent)
}

/// SPP instructions that finish by emitting an event.
fn is_general_event_source_tag(tag_byte: u8) -> bool {
    matches!(
        tag_byte,
        tag::DEPOSIT
            | tag::RING_DEPOSIT
            | tag::TRANSACT
            | tag::RING_TRANSACT
            | tag::RING_AUTHORITY_TRANSACT
            | tag::MERGE_TRANSACT
            | tag::RING_MERGE_TRANSACT
    )
}

fn is_event_source(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction
            .data
            .first()
            .copied()
            .is_some_and(is_general_event_source_tag)
}

/// Ring programs CPI into SPP with a ring instruction tag; SPP is listed in the
/// account list for the `emit_event` self-CPI.
fn is_ring_wrapper_event_source(
    shielded_pool_program_id: Pubkey,
    instruction: &ParsedInstruction,
) -> bool {
    matches!(
        instruction.data.first().copied(),
        Some(
            tag::RING_DEPOSIT
                | tag::RING_TRANSACT
                | tag::RING_AUTHORITY_TRANSACT
                | tag::RING_MERGE_TRANSACT
        )
    ) && instruction.accounts.contains(&shielded_pool_program_id)
}

fn is_emit_event(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction.data.first() == Some(&tag::EMIT_EVENT)
}
