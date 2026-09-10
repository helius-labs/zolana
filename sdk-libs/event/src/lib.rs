//! Indexer-side helpers for the shielded pool's `EMIT_EVENT` self-CPI: locating
//! events in a transaction and rebuilding the full event from the parent
//! instruction. The event layout itself lives in `zolana_interface::event`.

mod discovery;
pub mod reconstruction;

pub use discovery::*;
