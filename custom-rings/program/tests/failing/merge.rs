use custom_ring_interface::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{
    anonymous_config_account, auditor_pubkey, authority, escrowed_config_account,
    initialized_config_account, legacy_auditor_pubkey, merge_fixture, merge_fixture_with,
    merge_ring_data, setup_mollusk,
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
    merge_fixture_with(initialized_config_account(authority(), auditor_pubkey(4)))
        .expect_spp_cpi(&mollusk);
    merge_fixture_with(escrowed_config_account()).expect_spp_cpi(&mollusk);
}

/// A merge has no auditor proof and must not enter an anonymous ring.
#[test]
fn an_anonymous_merge_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut audited = merge_fixture_with(anonymous_config_account());
    *audited.data_mut() = merge_ring_data(Some(auditor_pubkey(4)));
    audited.expect_err(&mollusk, custom(CustomRingError::InvalidMergeDisclosure));
    merge_fixture_with(anonymous_config_account())
        .expect_err(&mollusk, custom(CustomRingError::InvalidMergeDisclosure));
    let mut other = merge_fixture_with(anonymous_config_account());
    let mut recipient = auditor_pubkey(4);
    recipient[9] ^= 1;
    *other.data_mut() = merge_ring_data(Some(recipient));
    other.expect_err(&mollusk, custom(CustomRingError::InvalidMergeDisclosure));
}

#[test]
fn a_legacy_auditor_key_refuses_the_merge_exactly() {
    let (mollusk, _) = setup_mollusk();
    merge_fixture_with(initialized_config_account(
        authority(),
        legacy_auditor_pubkey(),
    ))
    .expect_err(&mollusk, custom(CustomRingError::LegacyAuditorKey));
}
