use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_interface::custom_ring::{tag, RingProgramConfig, RING_PROGRAM_CONFIG};
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    auditor_pubkey, authority, config_pda, create_config_data, create_config_fixture,
    create_config_fixture_deployed_by, initialized_config_account, program_data_account,
    program_id, setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// Pins the green fixture: without it the negatives below could pass for the
/// wrong reason (a fixture that never reaches the checked code).
#[test]
fn create_config_writes_the_config_account() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture(auditor_pubkey(2));
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);

    let (config, bump) = config_pda();
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config)
        .map(|(_, account)| account.clone())
        .expect("config account in result");
    assert_eq!(written.owner, program_id());
    assert_eq!(
        written.data.len(),
        core::mem::size_of::<RingProgramConfig>()
    );
    assert_eq!(
        bytemuck::from_bytes::<RingProgramConfig>(&written.data),
        &RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority: pinocchio::Address::new_from_array(authority().to_bytes()),
            auditor_pubkey: auditor_pubkey(2),
            bump,
        }
    );
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    *fixture.data_mut() = vec![tag::CREATE_CONFIG, 1, 2, 3];
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.data_mut().push(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn missing_accounts_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let instruction = Instruction {
        program_id: program_id(),
        accounts: Vec::new(),
        data: create_config_data(auditor_pubkey(2)),
    };
    expect_err_exact(
        &mollusk,
        &instruction,
        &[],
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn unsigned_payer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.unsign("payer");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn unsigned_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.unsign("authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn readonly_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.set_writable("config", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.substitute("system_program", Pubkey::new_from_array([31; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn uncompressed_auditor_pubkey_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture(auditor_pubkey(4));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
    // 0x04 is the SEC1 uncompressed prefix: the stored key must be compressed.
}

#[test]
fn zero_prefix_auditor_pubkey_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture(auditor_pubkey(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
}

#[test]
fn reserved_auditor_keys_are_rejected_exactly() {
    for key in [
        zolana_interface::P_CONST_SEC1,
        zolana_interface::P_DERIVE_SEC1,
        zolana_interface::P_PDA_SEC1,
    ] {
        let (mollusk, _) = setup_mollusk();
        let fixture = create_config_fixture(key);
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
    }
}

#[test]
fn non_canonical_config_pda_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.substitute("config", Pubkey::new_from_array([41; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidConfigPda));
}

#[test]
fn double_initialization_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.set_account(
        "config",
        initialized_config_account(authority(), auditor_pubkey(2)),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigAlreadyInitialized));
}

#[test]
fn foreign_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let other = Pubkey::new_from_array([42; 32]);
    let fixture = create_config_fixture_deployed_by(auditor_pubkey(2), Some(&other));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn unset_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture_deployed_by(auditor_pubkey(2), None);
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn zeroed_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let zero = Pubkey::new_from_array([0; 32]);
    let fixture = create_config_fixture_deployed_by(auditor_pubkey(2), Some(&zero));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn foreign_program_data_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.substitute("program_data", Pubkey::new_from_array([43; 32]));
    fixture.set_account("program_data", program_data_account(Some(&authority())));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn foreign_program_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    fixture.substitute("program", Pubkey::new_from_array([44; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn truncated_program_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(2));
    let mut truncated = program_data_account(Some(&authority()));
    truncated.data.truncate(8);
    fixture.set_account("program_data", truncated);
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}
