//! The sender's spend record on a velocity ring.

pub(crate) mod discovery;
mod instruction;

pub use discovery::{LiveSpendRecord, ReadSpendRecord, RecordOrigin};
pub use instruction::{
    AsyncSpendProofEnvironment, ProvenSpendRegistration, RegisterSpend, SpendProofEnvironment,
};
