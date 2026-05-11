#[cfg(test)]
mod tests {
    use shielded_pool_program::process_instruction;
    use zolana_interface::instruction::{encode_instruction, tag, BatchUpdateAddressTreeData};

    #[test]
    fn batch_update_without_accounts_does_not_succeed() {
        let data = encode_instruction(
            tag::BATCH_UPDATE_ADDRESS_TREE,
            &BatchUpdateAddressTreeData {
                start_index: 0,
                new_root: [7u8; 32],
                proof_hash: [9u8; 32],
            },
        );
        let program_id = pinocchio::Address::from([0u8; 32]);

        assert!(process_instruction(&program_id, &[], &data).is_err());
    }
}
