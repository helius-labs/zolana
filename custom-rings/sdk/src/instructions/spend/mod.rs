//! The sender's spend record on a velocity ring.

mod discovery;
mod instruction;

pub use discovery::{LiveSpendRecord, ReadSpendRecord, RecordOrigin};
pub use instruction::{ProvenSpendRegistration, RegisterSpend, SpendProofEnvironment};
