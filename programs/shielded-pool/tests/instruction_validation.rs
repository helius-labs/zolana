use shielded_pool_program::process_instruction;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, AppendStateLeavesData, BatchUpdateAddressTreeData,
        CreatePoolTreeData, InsertAddressesData,
    },
    CPI_AUTHORITY_PDA_SEED, LIGHT_REGISTRY_CPI_AUTHORITY, LIGHT_REGISTRY_PROGRAM_ID,
};

fn program_id() -> pinocchio::Address {
    pinocchio::Address::new_from_array([0u8; 32])
}

#[test]
fn rejects_create_pool_tree_without_accounts() {
    let data = encode_instruction(tag::CREATE_POOL_TREE, &CreatePoolTreeData);
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_empty_insert_batch() {
    let data = encode_instruction(
        tag::INSERT_ADDRESSES,
        &InsertAddressesData { addresses: vec![] },
    );
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_empty_append_state_leaves_batch() {
    let data = encode_instruction(
        tag::APPEND_STATE_LEAVES,
        &AppendStateLeavesData { leaves: vec![] },
    );
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_malformed_payload() {
    let data = vec![tag::INSERT_ADDRESSES, 1, 2, 3];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn rejects_unknown_instruction_tag() {
    let data = vec![255];
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn non_empty_insert_without_accounts_does_not_succeed() {
    let data = encode_instruction(
        tag::INSERT_ADDRESSES,
        &InsertAddressesData {
            addresses: vec![[1u8; 32]],
        },
    );
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn non_empty_append_state_leaves_without_accounts_does_not_succeed() {
    let data = encode_instruction(
        tag::APPEND_STATE_LEAVES,
        &AppendStateLeavesData {
            leaves: vec![[1u8; 32]],
        },
    );
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

#[test]
fn encodes_first_byte_tags() {
    let data = encode_instruction(tag::CREATE_POOL_TREE, &CreatePoolTreeData);
    assert_eq!(data[0], tag::CREATE_POOL_TREE);
}

#[test]
fn batch_update_rejects_call_without_accounts() {
    // No accounts at all: the loader rejects before we even reach the
    // CPI-authority check, but we exercise the path anyway.
    let payload = BatchUpdateAddressTreeData {
        new_root: [1u8; 32],
        compressed_proof_a: [0u8; 32],
        compressed_proof_b: [0u8; 64],
        compressed_proof_c: [0u8; 32],
    };
    let data = encode_instruction(tag::BATCH_UPDATE_ADDRESS_TREE, &payload);
    assert!(process_instruction(&program_id(), &mut [], &data).is_err());
}

/// Pin the hardcoded `LIGHT_REGISTRY_CPI_AUTHORITY` to what
/// `Pubkey::find_program_address(b"cpi_authority", LIGHT_REGISTRY_PROGRAM_ID)`
/// actually returns. A rename of either the seed (in light-registry's
/// `constants.rs`) or the program id (in `declare_id!`) will trip this.
#[test]
fn cpi_authority_constant_matches_find_program_address() {
    let registry = Pubkey::new_from_array(LIGHT_REGISTRY_PROGRAM_ID);
    let (expected, _bump) = Pubkey::find_program_address(&[CPI_AUTHORITY_PDA_SEED], &registry);
    assert_eq!(expected.to_bytes(), LIGHT_REGISTRY_CPI_AUTHORITY);
}

#[test]
fn light_registry_program_id_matches_declared_id() {
    // Sanity check that LIGHT_REGISTRY_PROGRAM_ID is the right base58 program
    // id — a renamed `declare_id!` in `light-registry` should be loud.
    use std::str::FromStr;
    let parsed = Pubkey::from_str("Lighton6oQpVkeewmo2mcPTQQp7kYHr4fWpAgJyEmDX").unwrap();
    assert_eq!(parsed.to_bytes(), LIGHT_REGISTRY_PROGRAM_ID);
}
