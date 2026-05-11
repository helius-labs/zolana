#[cfg(test)]
mod tests {
    #[test]
    fn registry_program_id_is_wired_locally() {
        assert_ne!(light_registry::ID.to_bytes(), [0u8; 32]);
    }
}
