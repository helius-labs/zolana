//! Entry-mutation input validation, each branch refused before the SPP CPI.

use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_ring_policy::ListId;

use crate::common::{
    authority, create_entry_fixture, create_entry_fixture_with, default_entry_member,
    initialized_policy_config_account, setup_mollusk, update_entry_fixture,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The zero member is the padding value and never a real subject.
#[test]
fn a_zero_member_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    create_entry_fixture_with(
        initialized_policy_config_account(),
        ListId::Allow as u8,
        authority(),
        [0u8; 32],
        1,
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyMember));
}

/// A state byte outside the Active or Cleared discriminants is refused.
#[test]
fn an_out_of_range_state_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    create_entry_fixture_with(
        initialized_policy_config_account(),
        ListId::Allow as u8,
        authority(),
        default_entry_member(),
        99,
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidEntryState));
}

/// The namespace account must be the ring's own derived PDA.
#[test]
fn a_foreign_namespace_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_entry_fixture(
        initialized_policy_config_account(),
        ListId::Allow as u8,
        authority(),
    );
    fixture.substitute("entries", Pubkey::new_from_array([99u8; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidNamespacePda));
}

/// The successor is the spent version plus one, the ceiling freezes the lineage.
#[test]
fn a_version_at_the_ceiling_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    update_entry_fixture(
        initialized_policy_config_account(),
        ListId::Allow as u8,
        authority(),
        default_entry_member(),
        u64::MAX,
    )
    .expect_err(&mollusk, custom(CustomRingError::EntryVersionOverflow));
}
