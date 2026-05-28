#[cfg(test)]
mod tests {
    use shielded_pool_program::process_instruction;
    use zolana_interface::instruction::{
        encode_instruction, tag, BatchUpdateAddressTreeData, BatchUpdateNullifierTreeData,
    };

    #[test]
    fn batch_update_without_accounts_does_not_succeed() {
        let data = encode_instruction(
            tag::BATCH_UPDATE_ADDRESS_TREE,
            &BatchUpdateAddressTreeData {
                new_root: [7u8; 32],
                compressed_proof_a: [1u8; 32],
                compressed_proof_b: [2u8; 64],
                compressed_proof_c: [3u8; 32],
            },
        );
        let program_id = pinocchio::Address::new_from_array([0u8; 32]);

        assert!(process_instruction(&program_id, &mut [], &data).is_err());
    }

    #[test]
    fn nullifier_batch_update_without_accounts_does_not_succeed() {
        let data = encode_instruction(
            tag::BATCH_UPDATE_NULLIFIER_TREE,
            &BatchUpdateNullifierTreeData {
                address_new_root: [7u8; 32],
                address_compressed_proof_a: [1u8; 32],
                address_compressed_proof_b: [2u8; 64],
                address_compressed_proof_c: [3u8; 32],
                nullifier_new_root: [8u8; 32],
                nullifier_compressed_proof_a: [4u8; 32],
                nullifier_compressed_proof_b: [5u8; 64],
                nullifier_compressed_proof_c: [6u8; 32],
            },
        );
        let program_id = pinocchio::Address::new_from_array([0u8; 32]);

        assert!(process_instruction(&program_id, &mut [], &data).is_err());
    }
}
