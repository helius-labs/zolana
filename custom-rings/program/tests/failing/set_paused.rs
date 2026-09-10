//! `set_paused` negatives, the SPP CPI itself runs only on localnet.

use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;

use crate::common::{account, set_paused_fixture, setup_mollusk};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn set_paused_with_an_unsigned_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_paused_fixture(1);
    fixture.unsign("authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn set_paused_by_a_foreign_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_paused_fixture(1);
    fixture.substitute("authority", Pubkey::new_from_array([9u8; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn set_paused_before_the_config_exists_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_paused_fixture(1);
    fixture.set_account("config", account(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
}

#[test]
fn a_paused_byte_above_one_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_paused_fixture(2);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn set_paused_with_trailing_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_paused_fixture(1);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn set_paused_with_an_impostor_spp_program_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_paused_fixture(1);
    fixture.substitute("spp_program", Pubkey::new_from_array([61; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn set_paused_on_a_readonly_ring_auth_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_paused_fixture(1);
    fixture.set_writable("ring_auth", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn pause_and_resume_reach_the_spp_cpi() {
    let (mollusk, _) = setup_mollusk();
    for paused in [0, 1] {
        set_paused_fixture(paused).expect_spp_cpi(&mollusk);
    }
}
