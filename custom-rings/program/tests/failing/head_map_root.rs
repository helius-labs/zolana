//! Pins canonical root initialization and forbids resetting an advanced map.

use custom_ring_interface::{HeadMapRoot, HEAD_MAP_EMPTY_ROOT, HEAD_MAP_ROOT};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::{InstructionResult, ProgramResult};
use solana_pubkey::Pubkey;

use crate::common::{
    account, create_head_map_root_fixture, custom, head_map_root_account, head_map_root_pda,
    setup_mollusk, stored,
};

fn stored_root(result: &InstructionResult) -> HeadMapRoot {
    stored(result, head_map_root_pda().0)
}

#[test]
fn create_head_map_root_writes_the_empty_root_at_the_canonical_bump() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_head_map_root_fixture(None);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored_root(&result);
    assert_eq!(written.discriminator, HEAD_MAP_ROOT);
    assert_eq!(written.root, HEAD_MAP_EMPTY_ROOT);
    assert_eq!(written.next_index(), 1);
    assert_eq!(written.bump, head_map_root_pda().1);
}

#[test]
fn create_head_map_root_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_head_map_root_fixture(None);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn create_head_map_root_at_a_non_canonical_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_head_map_root_fixture(None);
    fixture.substitute("head_map_root", Pubkey::new_from_array([9; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidHeadMapRoot));
}

#[test]
fn create_head_map_root_with_a_wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_head_map_root_fixture(None);
    fixture.substitute("system_program", Pubkey::new_from_array([68; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn prefunding_the_empty_root_pda_does_not_prevent_initialization() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_head_map_root_fixture(Some(account(1_000_000)));
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    assert_eq!(stored_root(&result).root, HEAD_MAP_EMPTY_ROOT);
    assert_eq!(stored_root(&result).next_index(), 1);
}

#[test]
fn authority_cannot_reinitialize_an_advanced_root() {
    let (mollusk, _) = setup_mollusk();
    let advanced = head_map_root_account([0x11; 32], 19);
    let fixture = create_head_map_root_fixture(Some(advanced));
    fixture.expect_err(&mollusk, custom(CustomRingError::HeadMapRootAlreadyExists));
}

#[test]
fn create_head_map_root_with_trailing_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_head_map_root_fixture(None);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}
