//! `check_mutator` authorization on the entry-mutation path, both `Writer` arms.

use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_ring_policy::ListId;

use crate::common::{create_entry_fixture, initialized_policy_config_account, payer, setup_mollusk};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// The tag the create_entry fixture derives its member from.
fn member_payer() -> Pubkey {
    Pubkey::new_from_array([61u8; 32])
}

/// An authority-written list refuses a payer that is not the config authority.
#[test]
fn an_authority_written_list_rejects_a_non_authority_payer() {
    let (mollusk, _) = setup_mollusk();
    create_entry_fixture(
        initialized_policy_config_account(),
        ListId::Allow as u8,
        payer(),
    )
    .expect_err(&mollusk, custom(CustomRingError::UnauthorizedNamespaceSigner));
}

/// A member-written list refuses a payer whose owner tag is not the entry member.
#[test]
fn a_member_written_list_rejects_a_mismatched_payer() {
    let (mollusk, _) = setup_mollusk();
    create_entry_fixture(
        initialized_policy_config_account(),
        ListId::Escrow as u8,
        payer(),
    )
    .expect_err(&mollusk, custom(CustomRingError::UnauthorizedNamespaceSigner));
}

/// The matching member payer clears the writer gate and reaches the unloaded CPI.
#[test]
fn a_member_written_list_admits_the_matching_payer() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_entry_fixture(
        initialized_policy_config_account(),
        ListId::Escrow as u8,
        member_payer(),
    );
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_ne!(result.program_result, ProgramResult::Success);
    assert_ne!(
        result.program_result,
        ProgramResult::Failure(custom(CustomRingError::UnauthorizedNamespaceSigner))
    );
}
