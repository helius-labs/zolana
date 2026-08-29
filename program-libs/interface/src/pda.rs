use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    ASSOCIATED_TOKEN_PROGRAM_ID, DEFAULT_SOL_INTERFACE_INDEX_SEED, NULLIFIER_PDA_SEED,
    RING_AUTH_PDA_SEED, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
    SOL_INTERFACE_PDA_SEED, SPL_ASSET_COUNTER_PDA_SEED, SPL_ASSET_REGISTRY_PDA_SEED,
    SPL_INTERFACE_PDA_SEED, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
    SPP_PROTOCOL_CONFIG_PDA_SEED,
};

pub fn shielded_pool_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

pub fn shielded_pool_cpi_authority() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY)
}

pub fn protocol_config() -> Pubkey {
    Pubkey::find_program_address(&[SPP_PROTOCOL_CONFIG_PDA_SEED], &shielded_pool_program_id()).0
}

/// The shielded-pool program's `ProgramData` account under the upgradeable BPF
/// loader; `create_protocol_config` reads the deploy upgrade authority from it.
pub fn program_data() -> Pubkey {
    Pubkey::find_program_address(
        &[shielded_pool_program_id().as_ref()],
        &crate::BPF_LOADER_UPGRADEABLE_PUBKEY,
    )
    .0
}

pub fn sol_interface() -> Pubkey {
    sol_interface_with_bump().0
}

pub fn sol_interface_with_bump() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SOL_INTERFACE_PDA_SEED, DEFAULT_SOL_INTERFACE_INDEX_SEED],
        &shielded_pool_program_id(),
    )
}

pub fn spl_asset_counter() -> Pubkey {
    Pubkey::find_program_address(&[SPL_ASSET_COUNTER_PDA_SEED], &shielded_pool_program_id()).0
}

pub fn spl_asset_registry(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[SPL_ASSET_REGISTRY_PDA_SEED, mint.as_ref()],
        &shielded_pool_program_id(),
    )
    .0
}

pub fn spl_interface(mint: &Pubkey) -> Pubkey {
    spl_interface_with_bump(mint).0
}

pub fn spl_interface_with_bump(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SPL_INTERFACE_PDA_SEED, mint.as_ref()],
        &shielded_pool_program_id(),
    )
}

pub fn spl_interface_bump(mint: &[u8; 32]) -> u8 {
    spl_interface_with_bump(&Pubkey::new_from_array(*mint)).1
}

pub fn associated_token_program_id() -> Pubkey {
    Pubkey::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID)
}

pub fn spl_token_program_id() -> Pubkey {
    Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
}

pub fn spl_token_2022_program_id() -> Pubkey {
    Pubkey::new_from_array(SPL_TOKEN_2022_PROGRAM_ID)
}

/// Canonical associated token account for `(owner, mint)` under the SPL Token program.
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    associated_token_address_with_program(owner, mint, &spl_token_program_id())
}

/// Canonical associated token account for `(owner, mint)` under `token_program`.
pub fn associated_token_address_with_program(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program_id(),
    )
    .0
}

pub fn ring_auth(ring_program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], ring_program)
}

pub fn ring_auth_with_bump(ring_program: &Pubkey, bump: u8) -> Result<Pubkey, PubkeyError> {
    let bump = [bump];
    Pubkey::create_program_address(&[RING_AUTH_PDA_SEED, bump.as_slice()], ring_program)
}

pub fn nullifier_pda(tree: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[NULLIFIER_PDA_SEED, tree.as_ref(), nullifier],
        &shielded_pool_program_id(),
    )
}

#[cfg(test)]
mod tests {
    use solana_pubkey::Pubkey;

    use crate::{NULLIFIER_PDA_SEED, SOL_INTERFACE};

    #[test]
    fn nullifier_pda_bump_recreates_address() {
        let tree = Pubkey::new_unique();
        let nullifier = [7u8; 32];
        let (address, bump) = super::nullifier_pda(&tree, &nullifier);
        let recreated = Pubkey::create_program_address(
            &[NULLIFIER_PDA_SEED, tree.as_ref(), &nullifier, &[bump]],
            &super::shielded_pool_program_id(),
        )
        .expect("canonical bump is on the curve complement");
        assert_eq!(recreated, address);
        assert_ne!(
            super::nullifier_pda(&Pubkey::new_unique(), &nullifier).0,
            address
        );
        assert_ne!(super::nullifier_pda(&tree, &[8u8; 32]).0, address);
    }

    #[test]
    fn nullifier_pda_matches_typescript_vector() {
        let tree = Pubkey::from_str_const("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
        let expected = Pubkey::from_str_const("FketprhoGrMJG7tu9XaXEXhm4vCqzEubwMPFm874xtMm");
        assert_eq!(super::nullifier_pda(&tree, &[7u8; 32]), (expected, 252));
    }

    #[test]
    fn cpi_authority_const_matches_derivation() {
        let (address, bump) = Pubkey::find_program_address(
            &[crate::SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED],
            &super::shielded_pool_program_id(),
        );
        assert_eq!(address.to_bytes(), crate::SHIELDED_POOL_CPI_AUTHORITY);
        assert_eq!(bump, crate::SHIELDED_POOL_CPI_AUTHORITY_BUMP);
    }

    #[test]
    fn sol_interface_const_matches_derivation() {
        let (address, bump) = super::sol_interface_with_bump();
        assert_eq!(address.to_bytes(), SOL_INTERFACE);
        assert_eq!(bump, crate::SOL_INTERFACE_BUMP);
    }

    #[test]
    fn spl_interface_bump_matches_canonical_derivation() {
        let mint = Pubkey::new_unique();
        let (address, bump) = super::spl_interface_with_bump(&mint);
        assert_eq!(super::spl_interface(&mint), address);
        assert_eq!(super::spl_interface_bump(&mint.to_bytes()), bump);
    }

    #[test]
    fn associated_token_address_is_canonical_pda() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let (expected, _) = Pubkey::find_program_address(
            &[
                owner.as_ref(),
                super::spl_token_program_id().as_ref(),
                mint.as_ref(),
            ],
            &super::associated_token_program_id(),
        );
        assert_eq!(super::associated_token_address(&owner, &mint), expected);
    }
}
