//! `init_spp_ring_config` negatives.
//!
//! The instruction ends in a CPI to SPP, which mollusk cannot execute (the SPP
//! binary is not loaded here), so only the pre-CPI validation is asserted. The
//! successful path is covered by the localnet end-to-end test.

use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_interface::custom_ring::tag;

use crate::common::{
    account, auditor_pubkey, authority, init_spp_ring_config_fixture, initialized_config_account,
    setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn valid_config() -> solana_account::Account {
    initialized_config_account(authority(), auditor_pubkey(2))
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = init_spp_ring_config_fixture(valid_config());
    *fixture.data_mut() = vec![tag::INIT_SPP_RING_CONFIG, 0];
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn missing_accounts_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = init_spp_ring_config_fixture(valid_config());
    fixture.truncate(4);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn unsigned_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = init_spp_ring_config_fixture(valid_config());
    fixture.unsign("authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn uninitialized_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = init_spp_ring_config_fixture(account(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
}

#[test]
fn foreign_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let foreign = Pubkey::new_from_array([99; 32]);
    let fixture =
        init_spp_ring_config_fixture(initialized_config_account(foreign, auditor_pubkey(2)));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = init_spp_ring_config_fixture(valid_config());
    fixture.substitute("spp_program", Pubkey::new_from_array([61; 32]));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn non_canonical_ring_auth_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = init_spp_ring_config_fixture(valid_config());
    fixture.substitute("ring_auth", Pubkey::new_from_array([62; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::MissingRingAuth));
}
