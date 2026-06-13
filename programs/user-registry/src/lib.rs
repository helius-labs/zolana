pub mod constants;
pub mod error;
pub mod instructions;
pub mod processor;
pub mod validation;

pub use processor::process_instruction;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
