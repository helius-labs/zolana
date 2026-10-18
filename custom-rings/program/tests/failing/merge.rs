use custom_ring_interface::{CustomRingError, CustomRingMergeIxData};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{
    anonymous_config_account, auditor_pubkey, authority, escrowed_config_account,
    initialized_config_account, legacy_auditor_pubkey, member_registry_root_account, merge_fixture,
    merge_fixture_with, merge_ring_data, ring_auth_pda, setup_mollusk,
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
fn merge_requires_the_canonical_member_registry_root() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.substitute("member_registry_root", Pubkey::new_from_array([73; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidMemberRegistryRoot));
}

#[test]
fn merge_rejects_an_unwritten_or_zero_root() {
    let (mollusk, _) = setup_mollusk();
    let mut unwritten = merge_fixture();
    unwritten.data_mut()[1] = 1;
    unwritten.expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));

    let mut zero = merge_fixture();
    zero.set_account(
        "member_registry_root",
        member_registry_root_account([0; 32], 1),
    );
    zero.expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));
}

#[test]
fn merge_rejects_trailing_or_truncated_compact_data() {
    let (mollusk, _) = setup_mollusk();
    let mut trailing = merge_fixture();
    trailing.push_data(0);
    trailing.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));

    let mut truncated = merge_fixture();
    truncated.data_mut().truncate(33);
    truncated.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn merge_rejects_the_default_owner_registry_flag() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    let mut request = CustomRingMergeIxData::deserialize(&fixture.instruction().data[1..]).unwrap();
    request.merge.eddsa_owner = true;
    let tag = fixture.instruction().data[0];
    *fixture.data_mut() = [vec![tag], request.serialize().unwrap()].concat();
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
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

/// Anonymous members have no registered key for the proved merge ciphertext.
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

/// A ring PDA cannot sign on entry, so naming `ring_auth` as the merge payer
/// is rejected.
#[test]
fn merge_rejects_ring_auth_as_the_payer() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.substitute("payer", ring_auth_pda().0);
    fixture.unsign("payer");
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingFundingSigner));
}

#[test]
fn merge_rejects_an_unsigned_payer() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = merge_fixture();
    fixture.unsign("payer");
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingFundingSigner));
}
