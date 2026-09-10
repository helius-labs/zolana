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

pub use deposit::{proofless_output, proofless_outputs};
pub use indexed::{
    event_kind_from_indexed, general_event_from_indexed, indexed_events_from_instruction_groups,
    instruction_may_emit_events, IndexedEvent,
};
pub use instruction::{InstructionGroup, ParsedInstruction};
pub use reconstruct::{
    merge_general_event, reconstruct_general_event, reconstruct_general_event_from_payload,
    transact_general_event,
};
pub use zolana_event::EventDecodeError;
