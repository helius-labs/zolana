use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{
    auditor_pubkey, authority, escrowed_config_account, initialized_config_account, merge_fixture,
    merge_fixture_with, setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn merge_reaches_the_spp_cpi() {
    let (mollusk, _) = setup_mollusk();
    merge_fixture().expect_spp_cpi(&mollusk);
}

#[test]
fn merge_rejects_an_impostor_spp_program() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.substitute("spp_program", Pubkey::new_from_array([71; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn merge_requires_the_custom_ring_authority() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.substitute("ring_config", Pubkey::new_from_array([72; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingRingAuth));
}

/// Only the address tree is pinned, a windowed ring merges in any tree.
#[test]
fn a_policy_merge_keeps_its_tree_choice() {
    let (mollusk, _) = setup_mollusk();
    merge_fixture_with(initialized_config_account(authority(), auditor_pubkey(2)))
        .expect_spp_cpi(&mollusk);
    merge_fixture_with(escrowed_config_account()).expect_spp_cpi(&mollusk);
}
