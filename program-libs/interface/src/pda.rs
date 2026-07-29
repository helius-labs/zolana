use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    ASSOCIATED_TOKEN_PROGRAM_ID, DEFAULT_SOL_INTERFACE_INDEX_SEED, SHIELDED_POOL_CPI_AUTHORITY,
    SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE_PDA_SEED, SPL_ASSET_COUNTER_PDA_SEED,
    SPL_ASSET_REGISTRY_PDA_SEED, SPL_ASSET_VAULT_PDA_SEED, SPL_TOKEN_2022_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID, SPP_PROTOCOL_CONFIG_PDA_SEED, ZONE_AUTH_PDA_SEED,
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

pub fn spl_asset_vault(mint: &Pubkey) -> Pubkey {
    spl_asset_vault_with_bump(mint).0
}

pub fn spl_asset_vault_with_bump(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.as_ref()],
        &shielded_pool_program_id(),
    )
}

pub fn spl_asset_vault_bump(mint: &[u8; 32]) -> u8 {
    spl_asset_vault_with_bump(&Pubkey::new_from_array(*mint)).1
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

pub fn zone_auth(zone_program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], zone_program)
}

pub fn zone_auth_with_bump(zone_program: &Pubkey, bump: u8) -> Result<Pubkey, PubkeyError> {
    let bump = [bump];
    Pubkey::create_program_address(&[ZONE_AUTH_PDA_SEED, bump.as_slice()], zone_program)
}

#[cfg(test)]
mod tests {
    use solana_pubkey::Pubkey;

    use crate::SOL_INTERFACE;

    #[test]
    fn sol_interface_const_matches_derivation() {
        let (address, bump) = super::sol_interface_with_bump();
        assert_eq!(address.to_bytes(), SOL_INTERFACE);
        assert_eq!(bump, crate::SOL_INTERFACE_BUMP);
    }

    #[test]
    fn spl_asset_vault_bump_matches_canonical_derivation() {
        let mint = Pubkey::new_unique();
        let (address, bump) = super::spl_asset_vault_with_bump(&mint);
        assert_eq!(super::spl_asset_vault(&mint), address);
        assert_eq!(super::spl_asset_vault_bump(&mint.to_bytes()), bump);
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
