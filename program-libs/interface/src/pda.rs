use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    DEFAULT_SOL_INTERFACE_INDEX_SEED, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
    SOL_INTERFACE_PDA_SEED, SPL_ASSET_COUNTER_PDA_SEED, SPL_ASSET_REGISTRY_PDA_SEED,
    SPL_ASSET_VAULT_PDA_SEED, SPP_PROTOCOL_CONFIG_PDA_SEED, SPP_ZONE_CONFIG_PDA_SEED,
    ZONE_AUTH_PDA_SEED,
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

pub fn sol_interface() -> Pubkey {
    Pubkey::find_program_address(
        &[SOL_INTERFACE_PDA_SEED, DEFAULT_SOL_INTERFACE_INDEX_SEED],
        &shielded_pool_program_id(),
    )
    .0
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
    Pubkey::find_program_address(
        &[SPL_ASSET_VAULT_PDA_SEED, mint.as_ref()],
        &shielded_pool_program_id(),
    )
    .0
}

pub fn zone_config(zone_program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SPP_ZONE_CONFIG_PDA_SEED, zone_program.as_ref()],
        &shielded_pool_program_id(),
    )
}

pub fn zone_config_with_bump(zone_program: &Pubkey, bump: u8) -> Result<Pubkey, PubkeyError> {
    let bump = [bump];
    Pubkey::create_program_address(
        &[
            SPP_ZONE_CONFIG_PDA_SEED,
            zone_program.as_ref(),
            bump.as_slice(),
        ],
        &shielded_pool_program_id(),
    )
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
    use crate::SOL_INTERFACE;

    #[test]
    fn sol_interface_const_matches_derivation() {
        assert_eq!(super::sol_interface().to_bytes(), SOL_INTERFACE);
    }
}
