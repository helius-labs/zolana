pub mod error;
pub mod events;
pub mod instructions;
pub mod pda;
pub mod processor;

pub use processor::process_instruction;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
