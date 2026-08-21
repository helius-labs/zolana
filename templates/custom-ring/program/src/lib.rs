pub use custom_ring_program::ID;

#[cfg(all(feature = "bpf-entrypoint", target_os = "solana"))]
mod entrypoint {
    pinocchio::entrypoint!(custom_ring_program::process_instruction);
}

#[cfg(test)]
mod tests {
    #[test]
    fn program_id_matches_generated_value() {
        assert_eq!(
            custom_ring_program::ID.to_string(),
            "{{program_id}}"
        );
    }
}
