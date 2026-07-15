pub(crate) mod processor;
pub mod verify;

pub use processor::{process_fill, FillProof};
// TODO: collapse this dir into a single fill.rs file
