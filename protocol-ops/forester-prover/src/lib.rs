//! Nullifier-tree batch proof construction and proving for protocol operators.
mod client;
mod error;
mod inputs;
mod key;
#[cfg(feature = "gnark")]
mod local;
mod proof;
mod witness;
pub use client::{redact_api_key, ProverClient};
pub use error::Error;
pub use inputs::BatchAddressAppendInputs;
pub use key::ProvingKeyReport;
pub(crate) use proof::Proof;
pub use witness::{build_inputs, reference_nullifier_tree, ReferenceNullifierTree};
pub mod indexed;
