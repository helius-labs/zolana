pub(crate) mod processor;
pub mod verify;

pub use processor::{process_create_swap, CreateProof, CreateSwapIxData, MarkerData};
// TODO: collapse this dir into a single create_swap.rs file
