use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{
    entries_tree, initialized_policy_config_account, merge_fixture, policy_merge_fixture,
    setup_mollusk, transfer_cap_policy_config_account, velocity_policy_config_account,
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

#[test]
fn a_windowed_merge_off_the_entries_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    // Both default trees are foreign to the policy's entries tree.
    policy_merge_fixture(velocity_policy_config_account())
        .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTree));
}

#[test]
fn a_windowed_merge_with_a_foreign_output_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_merge_fixture(velocity_policy_config_account());
    fixture.substitute("input_tree", entries_tree());
    // The output tree stays foreign.
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTree));
}

#[test]
fn a_windowed_merge_into_the_entries_tree_reaches_the_spp_cpi() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_merge_fixture(velocity_policy_config_account());
    fixture.substitute("input_tree", entries_tree());
    fixture.substitute("output_tree", entries_tree());
    fixture.expect_spp_cpi(&mollusk);
}

#[test]
fn a_per_transfer_merge_keeps_its_tree_choice() {
    let (mollusk, _) = setup_mollusk();
    policy_merge_fixture(transfer_cap_policy_config_account()).expect_spp_cpi(&mollusk);
}

#[test]
fn an_ordinary_policy_merge_keeps_its_tree_choice() {
    let (mollusk, _) = setup_mollusk();
    policy_merge_fixture(initialized_policy_config_account()).expect_spp_cpi(&mollusk);
}
