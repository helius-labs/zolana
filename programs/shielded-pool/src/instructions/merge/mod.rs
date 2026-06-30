pub(crate) mod account;
pub(crate) mod event;
pub(crate) mod processor;
pub(crate) mod verify;

pub use processor::process_merge_transact_ix;
