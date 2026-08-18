//! {{project-name}}, a custom ring at `{{program_id}}`.
//!
//! The ring's instructions, proof verification and state come from
//! `custom-ring-program`; this crate pins the deploy address (see
//! `.cargo/config.toml`) and provides the entrypoint.

pub use custom_ring_program::*;

#[cfg(all(feature = "bpf-entrypoint", target_os = "solana"))]
mod entrypoint {
    pinocchio::entrypoint!(custom_ring_program::process_instruction);
}
