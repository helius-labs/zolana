use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::tag,
    output_data::{decode_output_data, ProoflessOutput},
};

use crate::reconstruction::{general_event_from_site, ReconstructError};
use crate::{EventKind, GeneralEvent};

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
    /// Bytes after `EMIT_EVENT`: `[EventKind, borsh(body)]`. The body is a
    /// `GeneralEvent` for deposits, a fixed-size `TransactEvent` / `MergeEvent`
    /// for those state changes, or a `NullifierTreeUpdateEvent` for a batch
    /// update.
    pub payload: Vec<u8>,
    /// Instruction tag of the parent state transition.
    pub source_instruction_tag: u8,
    /// Parent-aware decode result. Compact transact and merge bodies cannot be
    /// decoded without their parent instruction, so reconstruction happens once
    /// while the parent is available instead of leaking parent buffers to every
    /// consumer.
    pub decoded: Result<GeneralEvent, ReconstructError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositOutputDecodeError {
    InvalidOutputData,
    MissingOutput,
    MissingDepositSplTransfer,
}

pub fn proofless_output(event: &GeneralEvent) -> Result<ProoflessOutput, DepositOutputDecodeError> {
    let output = event
        .outputs
        .first()
        .ok_or(DepositOutputDecodeError::MissingOutput)?;
    let proofless = decode_output_data(&output.data)
        .map_err(|_| DepositOutputDecodeError::InvalidOutputData)?;
    require_deposit(event)?;
    Ok(proofless)
}

/// Decode every output of a batched proofless `deposit` event, in slot order.
pub fn proofless_outputs(
    event: &GeneralEvent,
) -> Result<Vec<ProoflessOutput>, DepositOutputDecodeError> {
    if event.outputs.is_empty() {
        return Err(DepositOutputDecodeError::MissingOutput);
    }
    require_deposit(event)?;
    event
        .outputs
        .iter()
        .map(|output| {
            decode_output_data(&output.data)
                .map_err(|_| DepositOutputDecodeError::InvalidOutputData)
        })
        .collect()
}

fn require_deposit(event: &GeneralEvent) -> Result<(), DepositOutputDecodeError> {
    if event.spl_transfers.is_empty()
        || !event
            .spl_transfers
            .iter()
            .all(|transfer| transfer.is_deposit)
    {
        return Err(DepositOutputDecodeError::MissingDepositSplTransfer);
    }
    Ok(())
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

pub fn general_event_from_indexed(event: &IndexedEvent) -> Result<&GeneralEvent, ReconstructError> {
    event.decoded.as_ref().map_err(|error| *error)
}

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
            let Some(parent) = event_parent(group, index) else {
                continue;
            };
            if !is_event_source(shielded_pool_program_id, parent) {
                continue;
            }
            events.push(indexed_event(&instruction.data, parent));
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

fn indexed_event(data: &[u8], parent: &ParsedInstruction) -> IndexedEvent {
    let payload = data.get(1..).unwrap_or_default().to_vec();
    let source_instruction_tag = parent.data.first().copied().unwrap_or_default();
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        decoded: general_event_from_pubkey_site(
            source_instruction_tag,
            &parent.data,
            &parent.accounts,
            &payload,
        ),
        payload,
        source_instruction_tag,
    }
}

/// Parent-aware off-chain decoder for callers whose account list uses Solana
/// pubkeys. The conversion intentionally copies addresses here; the on-chain
/// instruction parser and external-data hash never call this helper.
pub fn general_event_from_pubkey_site(
    source_instruction_tag: u8,
    parent_data: &[u8],
    parent_accounts: &[Pubkey],
    payload: &[u8],
) -> Result<GeneralEvent, ReconstructError> {
    let account_addresses: Vec<[u8; 32]> = parent_accounts.iter().map(Pubkey::to_bytes).collect();
    general_event_from_site(
        source_instruction_tag,
        parent_data,
        &account_addresses,
        payload,
    )
}

/// The instruction that invoked this event, by stack height. One level up from
/// the event, which covers the ring-CPI case where the pool instruction is
/// itself an inner instruction.
fn event_parent(group: &InstructionGroup, event_index: usize) -> Option<&ParsedInstruction> {
    let event_height = group.inner.get(event_index)?.stack_height?;
    let parent_height = event_height.checked_sub(1)?;

    group
        .inner
        .get(..event_index)?
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| (group.outer.stack_height == Some(parent_height)).then_some(&group.outer))
}

fn is_event_source(shielded_pool_program_id: Pubkey, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction
            .data
            .first()
            .copied()
            .and_then(EventKind::for_source_instruction)
            .is_some()
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
