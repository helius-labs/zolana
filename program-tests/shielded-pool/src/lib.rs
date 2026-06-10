#[cfg(test)]
mod tests {
    use shielded_pool_program::process_instruction;
    use zolana_interface::instruction::{encode_instruction, tag, BatchUpdateAddressTreeData};

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
    fn retired_nullifier_batch_update_tag_is_rejected() {
        // Tag 53 (BATCH_UPDATE_NULLIFIER_TREE) was retired when the nullifier
        // tree collapsed into the Light batched address tree; the dispatch
        // must reject it like any unknown byte.
        let data = vec![53u8, 0, 0, 0];
        let program_id = pinocchio::Address::new_from_array([0u8; 32]);

        assert!(process_instruction(&program_id, &mut [], &data).is_err());
    }
}
