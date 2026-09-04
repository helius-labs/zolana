use solana_pubkey::Pubkey;
use zolana_interface::{
    pda, NULLIFIER_PDA_SEED, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_CPI_AUTHORITY_BUMP,
    SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED, SOL_INTERFACE, SOL_INTERFACE_BUMP, TREE_PDA_SEED,
};

#[test]
fn nullifier_pda_bump_recreates_address() {
    let tree = Pubkey::new_unique();
    let nullifier = [7u8; 32];
    let (address, bump) = pda::nullifier_pda(&tree, &nullifier);
    let recreated = Pubkey::create_program_address(
        &[NULLIFIER_PDA_SEED, tree.as_ref(), &nullifier, &[bump]],
        &pda::shielded_pool_program_id(),
    )
    .expect("canonical bump is on the curve complement");
    assert_eq!(recreated, address);
    assert_ne!(
        pda::nullifier_pda(&Pubkey::new_unique(), &nullifier).0,
        address
    );
    assert_ne!(pda::nullifier_pda(&tree, &[8u8; 32]).0, address);
}

#[test]
fn nullifier_pda_matches_typescript_vector() {
    let tree = Pubkey::from_str_const("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
    let expected = Pubkey::from_str_const("FketprhoGrMJG7tu9XaXEXhm4vCqzEubwMPFm874xtMm");
    assert_eq!(pda::nullifier_pda(&tree, &[7u8; 32]), (expected, 252));
}

#[test]
fn tree_pda_is_bound_to_tree_id() {
    let (address, bump) = pda::tree_with_bump(7);
    let recreated = Pubkey::create_program_address(
        &[TREE_PDA_SEED, &7u16.to_le_bytes(), &[bump]],
        &pda::shielded_pool_program_id(),
    )
    .expect("canonical bump is on the curve complement");
    assert_eq!(recreated, address);
    assert_eq!(pda::tree(7), address);
    assert_ne!(pda::tree(8), address);
    assert_ne!(pda::tree(7 << 8), address);
}

#[test]
fn cpi_authority_const_matches_derivation() {
    let (address, bump) = Pubkey::find_program_address(
        &[SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED],
        &pda::shielded_pool_program_id(),
    );
    assert_eq!(address.to_bytes(), SHIELDED_POOL_CPI_AUTHORITY);
    assert_eq!(bump, SHIELDED_POOL_CPI_AUTHORITY_BUMP);
}

#[test]
fn sol_interface_const_matches_derivation() {
    let (address, bump) = pda::sol_interface_with_bump();
    assert_eq!(address.to_bytes(), SOL_INTERFACE);
    assert_eq!(bump, SOL_INTERFACE_BUMP);
}

#[test]
fn spl_interface_bump_matches_canonical_derivation() {
    let mint = Pubkey::new_unique();
    let (address, bump) = pda::spl_interface_with_bump(&mint);
    assert_eq!(pda::spl_interface(&mint), address);
    assert_eq!(pda::spl_interface_bump(&mint.to_bytes()), bump);
}

#[test]
fn associated_token_address_is_canonical_pda() {
    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (expected, _) = Pubkey::find_program_address(
        &[
            owner.as_ref(),
            pda::spl_token_program_id().as_ref(),
            mint.as_ref(),
        ],
        &pda::associated_token_program_id(),
    );
    assert_eq!(pda::associated_token_address(&owner, &mint), expected);
}
