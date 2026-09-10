use solana_address::Address;
use zolana_interface::{
    instruction::tag,
    output_data::{decode_output_data, ProoflessOutput},
};

use crate::reconstruction::{general_event_from_site, ReconstructError};
use zolana_interface::event::{EventKind, GeneralEvent};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInstruction {
    pub program_id: Address,
    pub accounts: Vec<Address>,
    pub data: Vec<u8>,
    pub stack_height: Option<u32>,
}

impl ParsedInstruction {
    pub fn new(
        program_id: Address,
        accounts: Vec<Address>,
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

/// An `EMIT_EVENT` self-CPI together with the instruction that invoked it.
///
/// The payload alone is attacker-reachable: any program can CPI the pool with
/// `EMIT_EVENT` and forged bytes. What cannot be forged is the parent, so an
/// event is only trustworthy when its parent is a state-transitioning
/// instruction of the pool itself. [`find_event_sites`] applies that rule in one
/// place; every event consumer must go through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventSite<'a> {
    /// Instruction tag of the parent state transition.
    pub source_instruction_tag: u8,
    /// Bytes after `EMIT_EVENT`: `[EventKind, borsh(body)]`.
    pub payload: &'a [u8],
    /// The pool instruction that emitted the event. `transact` and `merge` log
    /// only the positions execution assigns, so the rest of their event is
    /// rebuilt from this instruction's data and accounts.
    pub parent: &'a ParsedInstruction,
}

impl EventSite<'_> {
    pub fn general_event(&self) -> Result<GeneralEvent, ReconstructError> {
        general_event_from_address_site(
            self.source_instruction_tag,
            &self.parent.data,
            &self.parent.accounts,
            self.payload,
        )
    }
}

/// Collect every `EMIT_EVENT` of `shielded_pool_program_id` whose parent is an
/// instruction of the same program with a tag `is_source_tag` accepts.
/// `is_source_tag` must never accept `EMIT_EVENT` itself, or an event could
/// parent another.
pub fn find_event_sites<'a>(
    shielded_pool_program_id: Address,
    groups: &'a [InstructionGroup],
    is_source_tag: impl Fn(u8) -> bool,
) -> Vec<EventSite<'a>> {
    let mut sites = Vec::new();
    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if !is_emit_event(shielded_pool_program_id, instruction) {
                continue;
            }
            let Some(parent) = event_parent(group, index) else {
                continue;
            };
            if parent.program_id != shielded_pool_program_id {
                continue;
            }
            let Some(source_instruction_tag) = parent.data.first().copied() else {
                continue;
            };
            if !is_source_tag(source_instruction_tag) {
                continue;
            }
            sites.push(EventSite {
                source_instruction_tag,
                payload: instruction.data.get(1..).unwrap_or_default(),
                parent,
            });
        }
    }
    sites
}

/// Whether a pool instruction with this tag emits a [`GeneralEvent`], as opposed
/// to a nullifier-tree update or nothing at all.
pub fn emits_general_event(source_instruction_tag: u8) -> bool {
    matches!(
        EventKind::for_source_instruction(source_instruction_tag),
        Some(EventKind::Deposit | EventKind::Transact | EventKind::Merge)
    )
}

pub fn indexed_events_from_instruction_groups(
    shielded_pool_program_id: Address,
    groups: &[InstructionGroup],
) -> Vec<IndexedEvent> {
    find_event_sites(shielded_pool_program_id, groups, |source| {
        EventKind::for_source_instruction(source).is_some()
    })
    .iter()
    .map(indexed_event)
    .collect()
}

pub fn instruction_may_emit_events(
    shielded_pool_program_id: Address,
    instruction: &ParsedInstruction,
) -> bool {
    is_event_source(shielded_pool_program_id, instruction)
        || is_ring_wrapper_event_source(shielded_pool_program_id, instruction)
}

fn indexed_event(site: &EventSite<'_>) -> IndexedEvent {
    IndexedEvent {
        tag: tag::EMIT_EVENT,
        decoded: site.general_event(),
        payload: site.payload.to_vec(),
        source_instruction_tag: site.source_instruction_tag,
    }
}

/// Parent-aware off-chain decoder for callers whose account list uses Solana
/// addresses. The conversion intentionally copies addresses here; the on-chain
/// instruction parser and external-data hash never call this helper.
pub fn general_event_from_address_site(
    source_instruction_tag: u8,
    parent_data: &[u8],
    parent_accounts: &[Address],
    payload: &[u8],
) -> Result<GeneralEvent, ReconstructError> {
    let account_addresses: Vec<[u8; 32]> = parent_accounts.iter().map(Address::to_bytes).collect();
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

fn is_event_source(shielded_pool_program_id: Address, instruction: &ParsedInstruction) -> bool {
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
    shielded_pool_program_id: Address,
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

fn is_emit_event(shielded_pool_program_id: Address, instruction: &ParsedInstruction) -> bool {
    instruction.program_id == shielded_pool_program_id
        && instruction.data.first() == Some(&tag::EMIT_EVENT)
}
