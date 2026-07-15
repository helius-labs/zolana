use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;

use crate::{tag, EventKind, GeneralEvent, ProoflessOutput};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
    pub stack_height: Option<u32>,
}

impl ParsedInstruction {
    pub fn new(
        program_id: Pubkey,
        accounts: Vec<Pubkey>,
        data: Vec<u8>,
        stack_height: Option<u32>,
    ) -> Self {
        Self {
            program_id,
            accounts,
            data,
            stack_height,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionGroup {
    pub outer: ParsedInstruction,
    pub inner: Vec<ParsedInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEvent {
    /// SPP instruction tag: always [`tag::EMIT_EVENT`] for logged events.
    pub tag: u8,
    /// Bytes after `EMIT_EVENT`: `[EventKind, borsh(GeneralEvent)]`.
    pub payload: Vec<u8>,
    pub decoded: Result<GeneralEvent, EventDecodeError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDecodeError {
    MissingInstructionTag,
    InvalidInstructionTag(u8),
    InvalidPayload,
    InvalidEventKind(u8),
    InvalidOutputData,
    MissingOutput,
    MissingDepositWithdraw,
}

pub fn decode_event_instruction(data: &[u8]) -> Result<GeneralEvent, EventDecodeError> {
    let (&instruction_tag, payload) = data
        .split_first()
        .ok_or(EventDecodeError::MissingInstructionTag)?;
    if instruction_tag != tag::EMIT_EVENT {
        return Err(EventDecodeError::InvalidInstructionTag(instruction_tag));
    }
    decode_event_payload(payload)
}

pub fn decode_event_payload(payload: &[u8]) -> Result<GeneralEvent, EventDecodeError> {
    let (&kind_byte, event_bytes) = payload
        .split_first()
        .ok_or(EventDecodeError::InvalidPayload)?;
    // Validate the kind envelope up front; every known kind currently decodes
    // to a `GeneralEvent`, so dispatch is a single arm until a kind needs its
    // own payload struct.
    EventKind::from_byte(kind_byte).ok_or(EventDecodeError::InvalidEventKind(kind_byte))?;
    GeneralEvent::try_from_slice(event_bytes).map_err(|_| EventDecodeError::InvalidPayload)
}

pub fn decode_output_data(data: &[u8]) -> Result<ProoflessOutput, EventDecodeError> {
    let crate::OutputDataEncoding::Plaintext(blob) =
        crate::OutputDataEncoding::try_from_slice(data)
            .map_err(|_| EventDecodeError::InvalidOutputData)?
    else {
        return Err(EventDecodeError::InvalidOutputData);
    };
    let (&scheme, body) = blob
        .split_first()
        .ok_or(EventDecodeError::InvalidOutputData)?;
    if scheme != 0 {
        return Err(EventDecodeError::InvalidOutputData);
    }
    ProoflessOutput::try_from_slice(body).map_err(|_| EventDecodeError::InvalidOutputData)
}

pub fn proofless_output(event: &GeneralEvent) -> Result<ProoflessOutput, EventDecodeError> {
    let output = event
        .outputs
        .first()
        .ok_or(EventDecodeError::MissingOutput)?;
    let proofless = decode_output_data(&output.data)?;
    let deposit_withdraw = event
        .deposit_withdraw
        .as_ref()
        .ok_or(EventDecodeError::MissingDepositWithdraw)?;
    if !deposit_withdraw.is_deposit {
        return Err(EventDecodeError::MissingDepositWithdraw);
    }
    Ok(proofless)
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

/// Returns the decoded [`GeneralEvent`] body when the indexed payload is valid.
pub fn general_event_from_indexed(event: &IndexedEvent) -> Result<&GeneralEvent, EventDecodeError> {
    match &event.decoded {
        Ok(general_event) => Ok(general_event),
        Err(err) => Err(*err),
    }
}

pub fn indexed_events_from_instruction_groups(
    shielded_pool_program_id: Pubkey,
    groups: &[InstructionGroup],
) -> Vec<IndexedEvent> {
    let mut events = Vec::new();
    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if is_emit_event(shielded_pool_program_id, instruction)
                && parent_is_event_source(shielded_pool_program_id, group, index)
            {
                events.push(indexed_event(&instruction.data));
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
        || is_zone_wrapper_event_source(shielded_pool_program_id, instruction)
}

fn indexed_event(data: &[u8]) -> IndexedEvent {
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        payload: data.get(1..).unwrap_or_default().to_vec(),
        decoded: decode_event_instruction(data),
    }
}

fn parent_is_event_source(
    shielded_pool_program_id: Pubkey,
    group: &InstructionGroup,
    event_index: usize,
) -> bool {
    let Some(event_height) = group.inner[event_index].stack_height else {
        return false;
    };
    let Some(parent_height) = event_height.checked_sub(1) else {
        return false;
    };

    let parent = group.inner[..event_index]
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| (group.outer.stack_height == Some(parent_height)).then_some(&group.outer));

    parent.is_some_and(|instruction| is_event_source(shielded_pool_program_id, instruction))
}

/// SPP instructions that finish by emitting a [`GeneralEvent`] via `emit_event`.
fn is_general_event_source_tag(tag_byte: u8) -> bool {
    matches!(
        tag_byte,
        tag::DEPOSIT
            | tag::ZONE_DEPOSIT
            | tag::TRANSACT
            | tag::ZONE_TRANSACT
            | tag::ZONE_AUTHORITY_TRANSACT
            | tag::MERGE_TRANSACT
            | tag::ZONE_MERGE_TRANSACT
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

/// Zone programs CPI into SPP with a zone instruction tag; SPP is listed in the
/// account list for the `emit_event` self-CPI.
fn is_zone_wrapper_event_source(
    shielded_pool_program_id: Pubkey,
    instruction: &ParsedInstruction,
) -> bool {
    matches!(
        instruction.data.first().copied(),
        Some(
            tag::ZONE_DEPOSIT
                | tag::ZONE_TRANSACT
                | tag::ZONE_AUTHORITY_TRANSACT
                | tag::ZONE_MERGE_TRANSACT
        )
    ) && instruction.accounts.contains(&shielded_pool_program_id)
}

fn is_emit_event(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction.data.first() == Some(&tag::EMIT_EVENT)
}
