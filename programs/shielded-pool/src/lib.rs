pub mod error;
pub mod instructions;
pub mod log;
pub mod processor;

pub use processor::process_instruction;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
pinocchio::address::declare_id!("8nhL4dQgcddkc8cNV5piaZ1zKGowap1XrS8EDKi4rywq");
