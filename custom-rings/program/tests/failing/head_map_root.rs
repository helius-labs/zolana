//! The compressed head-map root account.

use custom_ring_interface::{HeadMapRoot, HEAD_MAP_EMPTY_ROOT, HEAD_MAP_ROOT};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::{InstructionResult, ProgramResult};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::{create_head_map_root_fixture, head_map_root_pda, program_id, setup_mollusk};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn stored(result: &InstructionResult) -> HeadMapRoot {
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &head_map_root_pda().0)
        .map(|(_, account)| account.clone())
        .expect("head map root in result");
    assert_eq!(written.owner, program_id());
    *bytemuck::from_bytes::<HeadMapRoot>(&written.data)
}

#[test]
fn create_head_map_root_writes_the_empty_root_at_the_canonical_bump() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_head_map_root_fixture(None);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored(&result);
    assert_eq!(written.discriminator, HEAD_MAP_ROOT);
    assert_eq!(*written.root(), HEAD_MAP_EMPTY_ROOT);
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
