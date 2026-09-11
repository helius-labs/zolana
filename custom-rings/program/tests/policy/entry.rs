//! Entry-mutation input validation, each branch refused before the SPP CPI.

use custom_ring_program::CustomRingError;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_ring_policy::ListId;

use crate::common::{
    account, authority, initialized_policy_config_account, setup_mollusk, EntryFixture, Slot,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The zero member is the padding value and never a real subject.
#[test]
fn a_zero_member_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    EntryFixture {
        member: [0u8; 32],
        ..EntryFixture::new(ListId::Allow, authority())
    }
    .create(initialized_policy_config_account())
    .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyMember));
}

/// A state byte outside the Active or Cleared discriminants is refused.
#[test]
fn an_out_of_range_state_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    EntryFixture {
        state: 99,
        ..EntryFixture::new(ListId::Allow, authority())
    }
    .create(initialized_policy_config_account())
    .expect_err(&mollusk, custom(CustomRingError::InvalidEntryState));
}

/// Every list commits unit content, a nonzero commit has no typed view.
#[test]
fn content_on_a_unit_content_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    EntryFixture {
        content_hash: [1u8; 32],
        ..EntryFixture::new(ListId::Allow, authority())
    }
    .create(initialized_policy_config_account())
    .expect_err(&mollusk, custom(CustomRingError::InvalidEntryContent));
}

/// The spent content only rebuilds the spent leaf, the successor is gated.
#[test]
fn a_successor_with_content_on_a_unit_content_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    EntryFixture {
        content_hash: [1u8; 32],
        ..EntryFixture::new(ListId::Allow, authority())
    }
    .update(initialized_policy_config_account(), 0)
    .expect_err(&mollusk, custom(CustomRingError::InvalidEntryContent));
}

/// The namespace account must be the ring's own derived PDA.
#[test]
fn a_foreign_namespace_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        EntryFixture::new(ListId::Allow, authority()).create(initialized_policy_config_account());
    fixture.substitute("entries", Pubkey::new_from_array([99u8; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidNamespacePda));
}

/// The successor is the spent version plus one, the ceiling freezes the lineage.
#[test]
fn a_version_at_the_ceiling_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    EntryFixture::new(ListId::Allow, authority())
        .update(initialized_policy_config_account(), u64::MAX)
        .expect_err(&mollusk, custom(CustomRingError::EntryVersionOverflow));
}

#[test]
fn an_impostor_shielded_pool_program_on_a_mutation_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        EntryFixture::new(ListId::Allow, authority()).create(initialized_policy_config_account());
    fixture.substitute("spp_program", Pubkey::new_from_array([71; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn a_wrong_system_program_on_a_mutation_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = EntryFixture::new(ListId::Allow, authority())
        .update(initialized_policy_config_account(), 0);
    fixture.substitute("system_program", Pubkey::new_from_array([73; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn a_tenth_account_on_a_mutation_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture =
        EntryFixture::new(ListId::Allow, authority()).create(initialized_policy_config_account());
    fixture.push(Slot {
        label: "extra",
        meta: AccountMeta::new_readonly(Pubkey::new_from_array([74; 32]), false),
        account: account(1),
    });
    fixture.expect_err(&mollusk, ProgramError::InvalidArgument);
}

/// Zero is the inline-asset sentinel, nine is past the last list.
#[test]
fn a_list_byte_outside_the_lists_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    for list_byte in [0u8, 9] {
        EntryFixture {
            list_byte,
            ..EntryFixture::new(ListId::Allow, authority())
        }
        .create(initialized_policy_config_account())
        .expect_err(&mollusk, custom(CustomRingError::InvalidListId));
    }
}

#[test]
fn an_out_of_range_spent_state_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    EntryFixture {
        spent_state: 99,
        ..EntryFixture::new(ListId::Allow, authority())
    }
    .update(initialized_policy_config_account(), 0)
    .expect_err(&mollusk, custom(CustomRingError::InvalidEntryState));
}
