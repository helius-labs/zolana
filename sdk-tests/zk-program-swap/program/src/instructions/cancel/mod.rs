pub(crate) mod processor;
pub mod verify;

pub use processor::{process_cancel, CancelProof};
// TODO: collapse this dir into a single cancel.rs file
