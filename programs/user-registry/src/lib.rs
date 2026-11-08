pub mod error;
pub mod instructions;
pub mod processor;

pub use processor::process_instruction;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);

    solana_security_txt::security_txt! {
        name: "Solana Privacy Rings User Registry",
        project_url: "https://github.com/helius-labs/privacy-rings",
        contacts: "email:security@helius.xyz",
        policy: "Please report security vulnerabilities privately to security@helius.xyz."
    }
}
