use custom_ring_interface::{
    merge_anonymous_verifying_key, merge_disclosure_field_count, CustomRingError, MergeDisclosure,
};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{
    anonymous_config_account, audit_only_config_account, auditor_pubkey, authority,
    escrowed_config_account, initialized_config_account, member_registry_root_account,
    merge_disclosure, merge_fixture, merge_fixture_with, merge_ring_data, ring_auth_pda,
    setup_mollusk, Fixture,
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

fn anonymous_merge(disclosure: Option<MergeDisclosure>) -> Fixture {
    let mut fixture = merge_fixture_with(anonymous_config_account());
    *fixture.data_mut() = merge_ring_data(disclosure);
    fixture
}

/// SPP waives the escrow key for an anonymous merge, so the ring proves the disclosure first.
#[test]
fn an_anonymous_merge_requires_its_disclosure_proof() {
    let (mollusk, _) = setup_mollusk();
    anonymous_merge(None).expect_err(&mollusk, custom(CustomRingError::MissingMergeDisclosure));
    anonymous_merge(Some(merge_disclosure(merge_disclosure_field_count(24))))
        .expect_err(&mollusk, custom(CustomRingError::MergeDisclosureWidth));
    let mut untagged = merge_disclosure(merge_disclosure_field_count(8));
    untagged.eph_pk[0] = 2;
    anonymous_merge(Some(untagged))
        .expect_err(&mollusk, custom(CustomRingError::InvalidMergeDisclosure));
    let key_gate = match merge_anonymous_verifying_key(8) {
        Some(_) => CustomRingError::ProofVerificationFailed,
        None => CustomRingError::UnsupportedCircuit,
    };
    anonymous_merge(Some(merge_disclosure(merge_disclosure_field_count(8))))
        .expect_err(&mollusk, custom(key_gate));
}

/// Only an anonymous ring may set the SPP flag, a disclosure elsewhere is refused.
#[test]
fn a_registered_merge_refuses_a_disclosure() {
    let (mollusk, _) = setup_mollusk();
    for config in [
        audit_only_config_account(authority(), auditor_pubkey(4)),
        escrowed_config_account(),
    ] {
        let mut fixture = merge_fixture_with(config);
        *fixture.data_mut() =
            merge_ring_data(Some(merge_disclosure(merge_disclosure_field_count(8))));
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidMergeDisclosure));
    }
}

#[test]
fn merge_rejects_an_unknown_disclosure_tag() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = anonymous_merge(None);
    fixture.data_mut()[34] = 2;
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
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
