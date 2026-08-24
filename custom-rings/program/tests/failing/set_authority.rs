use custom_ring_interface::{RingProgramConfig, RING_PROGRAM_CONFIG};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use pinocchio::Address;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;

use crate::common::{
    account, auditor_pubkey, config_pda, new_authority, set_authority_fixture, setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn set_authority_writes_the_new_authority() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_authority_fixture();
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);

    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config_pda().0)
        .map(|(_, account)| account.clone())
        .expect("config in result");
    let config = bytemuck::from_bytes::<RingProgramConfig>(&written.data);
    assert_eq!(config.discriminator, RING_PROGRAM_CONFIG);
    assert_eq!(
        config.authority,
        Address::new_from_array(new_authority().to_bytes())
    );
    assert_eq!(config.auditor_pubkey, auditor_pubkey(2));
    assert_eq!(config.bump, config_pda().1);
}

#[test]
fn set_authority_on_a_readonly_config_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.set_writable("config", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn set_authority_on_a_foreign_config_account_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.substitute("config", Pubkey::new_from_array([12u8; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidConfigPda));
}

#[test]
fn set_authority_by_a_foreign_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.substitute("authority", Pubkey::new_from_array([9u8; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn set_authority_with_an_unsigned_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.unsign("authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn set_authority_with_an_unsigned_new_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.unsign("new_authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn set_authority_with_trailing_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.data_mut().push(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn set_authority_before_the_config_exists_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_authority_fixture();
    fixture.set_account("config", account(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
}
