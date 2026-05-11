#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use shielded_pool_program::process_instruction;
    use zolana_interface::instruction::{BatchUpdateAddressTreeData, ShieldedPoolInstruction};

    #[test]
    fn batch_update_accepts_non_zero_root() {
        let instruction =
            ShieldedPoolInstruction::BatchUpdateAddressTree(BatchUpdateAddressTreeData {
                start_index: 0,
                new_root: [7u8; 32],
                proof_hash: [9u8; 32],
            });
        let data = instruction.try_to_vec().unwrap();
        let program_id = pinocchio::Address::from([0u8; 32]);

        assert!(process_instruction(&program_id, &[], &data).is_ok());
    }
}
