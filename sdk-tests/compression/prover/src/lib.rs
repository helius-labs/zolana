pub mod ffi;
pub mod read;

pub use ffi::{build_dir, setup};
pub use read::{ProofError, ReadProofInputs};
