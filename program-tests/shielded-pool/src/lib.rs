#[cfg(test)]
mod tests {
    use shielded_pool_program::process_instruction;
    use zolana_interface::instruction::{encode_instruction, tag, CreateTreeData};

    #[test]
    fn create_tree_without_accounts_does_not_succeed() {
        let data = encode_instruction(tag::CREATE_TREE, &CreateTreeData);
        let program_id = pinocchio::Address::new_from_array([0u8; 32]);

        assert!(process_instruction(&program_id, &mut [], &data).is_err());
    }
}
