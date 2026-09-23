//! Pins key-registry root init and the register-key account checks before the proof.

use custom_ring_interface::{
    KeyRegistryRoot, HEAD_MAP_EMPTY_ROOT, KEY_REGISTRY_ROOT, KEY_REGISTRY_ROOT_HISTORY,
};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::{InstructionResult, ProgramResult};
use solana_pubkey::Pubkey;

use crate::common::{
    create_key_registry_root_fixture, custom, key_registry_root_account, key_registry_root_pda,
    payer, register_key_fixture, setup_mollusk, stored,
};

fn stored_root(result: &InstructionResult) -> KeyRegistryRoot {
    stored(result, key_registry_root_pda().0)
}

#[test]
fn create_key_registry_root_writes_the_empty_root_at_the_canonical_bump() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_key_registry_root_fixture(None);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = stored_root(&result);
    assert_eq!(written.discriminator, KEY_REGISTRY_ROOT);
    assert_eq!(written.root, HEAD_MAP_EMPTY_ROOT);
    assert_eq!(written.next_index(), 1);
    assert_eq!(written.bump, key_registry_root_pda().1);
    assert_eq!(written.history_cursor, 0);
    assert_eq!(written.root_at(0), Some(HEAD_MAP_EMPTY_ROOT));
    assert!((1..=KEY_REGISTRY_ROOT_HISTORY as u8).all(|index| written.root_at(index).is_none()));
}

/// The first four fields keep their offsets, the history is appended.
#[test]
fn the_registry_layout_appends_the_history() {
    assert_eq!(KeyRegistryRoot::SIZE, 1067);
    assert_eq!(core::mem::offset_of!(KeyRegistryRoot, root), 1);
    assert_eq!(core::mem::offset_of!(KeyRegistryRoot, next_index), 33);
    assert_eq!(core::mem::offset_of!(KeyRegistryRoot, bump), 41);
    assert_eq!(core::mem::offset_of!(KeyRegistryRoot, history_cursor), 42);
    assert_eq!(core::mem::offset_of!(KeyRegistryRoot, history), 43);
}

#[test]
fn create_key_registry_root_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_key_registry_root_fixture(None);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn create_key_registry_root_at_a_non_canonical_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_key_registry_root_fixture(None);
    fixture.substitute("key_registry_root", Pubkey::new_from_array([9; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidKeyRegistryRoot));
}

#[test]
fn authority_cannot_reinitialize_an_advanced_registry() {
    let (mollusk, _) = setup_mollusk();
    let advanced = key_registry_root_account([0x11; 32], 19);
    let fixture = create_key_registry_root_fixture(Some(advanced));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::KeyRegistryRootAlreadyExists),
    );
}

#[test]
fn create_key_registry_root_with_trailing_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_key_registry_root_fixture(None);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn a_register_key_on_a_fresh_root_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let root = key_registry_root_account(HEAD_MAP_EMPTY_ROOT, 1);
    let fixture = register_key_fixture(root, payer());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_register_key_against_a_stale_root_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let root = key_registry_root_account([0x99; 32], 1);
    let fixture = register_key_fixture(root, payer());
    fixture.expect_err(&mollusk, custom(CustomRingError::StaleKeyRegistryRoot));
}

#[test]
fn a_register_key_with_a_wrong_cursor_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let root = key_registry_root_account(HEAD_MAP_EMPTY_ROOT, 5);
    let fixture = register_key_fixture(root, payer());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidKeyRegistryCursor));
}
