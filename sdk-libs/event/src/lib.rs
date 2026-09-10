//! Shielded-pool event discovery and reconstruction for indexers.
//!
//! The program records an event by re-invoking itself with an `EMIT_EVENT`
//! instruction, so an event is an inner instruction. `deposit` emits the full
//! `GeneralEvent`; `transact` and `merge` emit only the values assigned at
//! execution ([`zolana_event::TransactEvent`], [`zolana_event::MergeEvent`]) and
//! this crate rebuilds the `GeneralEvent` from that body plus the data and
//! account list of the instruction that emitted it.
//!
//! Anyone can CPI the pool with `EMIT_EVENT` and forged bytes, so an event is
//! trusted only when its direct parent is a state-transitioning shielded-pool
//! instruction; [`indexed_events_from_instruction_groups`] applies that rule.

pub mod deposit;
pub mod indexed;
pub mod instruction;
pub mod reconstruct;

pub use deposit::{
    decode_encrypted_ring_deposit_output_data, decode_output_data, proofless_output,
    proofless_outputs,
};
pub use indexed::{
    event_kind_from_indexed, event_parent, general_event_from_indexed,
    indexed_events_from_instruction_groups, instruction_may_emit_events, IndexedEvent,
};
pub use instruction::{InstructionGroup, ParsedInstruction};
pub use reconstruct::{
    merge_general_event, reconstruct_general_event, reconstruct_general_event_from_payload,
    transact_general_event,
};

/// Why an emitted event or output payload could not be decoded or rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDecodeError {
    MissingInstructionTag,
    InvalidInstructionTag(u8),
    InvalidPayload,
    InvalidEventKind(u8),
    InvalidOutputData,
    MissingOutput,
    MissingDepositSplTransfer,
    /// The emitting instruction's data did not parse as the instruction the
    /// event kind belongs to.
    InvalidSourceInstructionData,
    /// The emitting instruction's tag cannot produce this event kind.
    UnsupportedSourceInstruction(u8),
    /// An output's `OwnerTag::Account` index points past the emitting
    /// instruction's account list.
    OutputOwnerAccountMissing(u8),
    /// The event names more input trees than the instruction data can assign
    /// inputs to.
    UnsupportedInputTreeCount(usize),
    /// The emitting instruction's account list is shorter than the settlement
    /// groups its interface transfers require.
    MissingSettlementAccount,
    /// The event kind carries no [`GeneralEvent`](zolana_event::GeneralEvent) view
    /// (nullifier-tree updates).
    NotAGeneralEvent,
    /// Queue sequence or leaf index arithmetic overflowed.
    IndexOverflow,
}
