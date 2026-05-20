#[cfg(test)]
mod tests {
    use shielded_pool_program::process_instruction;
    use zolana_interface::instruction::{encode_instruction, tag, BatchUpdateAddressTreeData};

    #[test]
    fn batch_update_without_accounts_does_not_succeed() {
        let data = encode_instruction(
            tag::BATCH_UPDATE_ADDRESS_TREE,
            &BatchUpdateAddressTreeData {
                cpi_authority_bump: 255,
                new_root: [7u8; 32],
                compressed_proof_a: [1u8; 32],
                compressed_proof_b: [2u8; 64],
                compressed_proof_c: [3u8; 32],
            },
        );
        let program_id = pinocchio::Address::new_from_array([0u8; 32]);

        assert!(process_instruction(&program_id, &[], &data).is_err());
    }
}
