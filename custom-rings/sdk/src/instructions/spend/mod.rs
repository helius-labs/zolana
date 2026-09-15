//! The sender's spend record on a velocity ring.

pub(crate) mod discovery;
mod instruction;

pub use discovery::{LiveSpendRecord, ReadEnvironment, ReadSpendRecord, RecordOrigin};
pub use instruction::{ProvenSpendRegistration, RegisterSpend};
