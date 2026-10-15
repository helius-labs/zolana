use custom_ring_interface::{tag, RingMode, RingProgramConfig, RING_PROGRAM_CONFIG};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, auditor_pubkey, authority, config_pda, create_config_data, create_config_data_with,
    create_config_data_with_tier, create_config_fixture, create_config_fixture_deployed_by,
    initialized_config_account, legacy_auditor_pubkey, program_data_account, program_id,
    setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// Pins the green fixture: without it the negatives below could pass for the
/// wrong reason (a fixture that never reaches the checked code).
#[test]
fn create_config_writes_the_config_account() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture(auditor_pubkey(4));
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
    assert_eq!(written.data.len(), 69);
    assert_eq!(
        bytemuck::from_bytes::<RingProgramConfig>(&written.data),
        &RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority: pinocchio::Address::new_from_array(authority().to_bytes()),
            auditor_pubkey: auditor_pubkey(4),
            bump,
            has_policy: 1,
            mode: 0,
        }
    );
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    *fixture.data_mut() = vec![tag::CREATE_CONFIG, 1, 2, 3];
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.data_mut().push(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn missing_accounts_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let instruction = Instruction {
        program_id: program_id(),
        accounts: Vec::new(),
        data: create_config_data(auditor_pubkey(4)),
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
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.unsign("payer");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn unsigned_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.unsign("authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn readonly_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.set_writable("config", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.substitute("system_program", Pubkey::new_from_array([31; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn p256_auditor_pubkey_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture(auditor_pubkey(2));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
    // P-256 keys cannot be reinterpreted as X25519 envelope keys.
}

#[test]
fn zero_prefix_auditor_pubkey_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture(auditor_pubkey(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
}

/// A low-order or non-canonical u would give the auditor a keystream that
/// ignores the ephemeral secret.
#[test]
fn low_order_and_non_canonical_auditor_keys_are_rejected_exactly() {
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut minus_one = [0xff; 32];
    minus_one[0] = 0xec;
    minus_one[31] = 0x7f;
    let mut modulus = minus_one;
    modulus[0] = 0xed;
    let order_eight: [u8; 32] =
        hex::decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
            .expect("hex")
            .try_into()
            .expect("32 bytes");
    let (mollusk, _) = setup_mollusk();
    for u in [[0u8; 32], one, minus_one, modulus, order_eight] {
        let mut key = [4u8; 33];
        key[1..].copy_from_slice(&u);
        let fixture = create_config_fixture(key);
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
    }
}

/// Prevents a ring from storing an auditor key whose ECDH result is always zero.
#[test]
fn low_order_auditor_keys_are_rejected_exactly() {
    for u_hex in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let mut key = [4; 33];
        key[1..].copy_from_slice(&hex::decode(u_hex).expect("valid low-order u"));
        let (mollusk, _) = setup_mollusk();
        create_config_fixture(key)
            .expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
    }
}

#[test]
fn non_canonical_config_pda_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.substitute("config", Pubkey::new_from_array([41; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidConfigPda));
}

#[test]
fn double_initialization_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.set_account(
        "config",
        initialized_config_account(authority(), auditor_pubkey(4)),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigAlreadyInitialized));
}

#[test]
fn foreign_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let other = Pubkey::new_from_array([42; 32]);
    let fixture = create_config_fixture_deployed_by(auditor_pubkey(4), Some(&other));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn unset_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_config_fixture_deployed_by(auditor_pubkey(4), None);
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn zeroed_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let zero = Pubkey::new_from_array([0; 32]);
    let fixture = create_config_fixture_deployed_by(auditor_pubkey(4), Some(&zero));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn foreign_program_data_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.substitute("program_data", Pubkey::new_from_array([43; 32]));
    fixture.set_account("program_data", program_data_account(Some(&authority())));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn foreign_program_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.substitute("program", Pubkey::new_from_array([44; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn truncated_program_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    let mut truncated = program_data_account(Some(&authority()));
    truncated.data.truncate(8);
    fixture.set_account("program_data", truncated);
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

/// Attacker-donated lamports at the config PDA take the cold creation path.
#[test]
fn donated_lamports_at_the_config_pda_still_initialize() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.set_account("config", account(1));
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config_pda().0)
        .map(|(_, account)| account.clone())
        .expect("config account in result");
    assert_eq!(
        bytemuck::from_bytes::<RingProgramConfig>(&written.data).discriminator,
        RING_PROGRAM_CONFIG
    );
}

/// ProgramData-shaped bytes at the program address fail the state check.
#[test]
fn a_program_account_without_program_state_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    fixture.set_account("program", program_data_account(Some(&authority())));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn a_tier_above_one_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    *fixture.data_mut() = create_config_data_with_tier(auditor_pubkey(4), 2);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn create_config_stores_an_audit_only_tier() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    *fixture.data_mut() = create_config_data_with_tier(auditor_pubkey(4), 0);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let (config, bump) = config_pda();
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config)
        .map(|(_, account)| account.clone())
        .expect("config account in result");
    assert_eq!(
        bytemuck::from_bytes::<RingProgramConfig>(&written.data),
        &RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority: pinocchio::Address::new_from_array(authority().to_bytes()),
            auditor_pubkey: auditor_pubkey(4),
            bump,
            has_policy: 0,
            mode: 0,
        }
    );
}

#[test]
fn noncanonical_x25519_auditor_keys_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut high_bit = auditor_pubkey(4);
    high_bit[32] |= 128;
    let mut modulus = [255; 33];
    modulus[0] = 4;
    modulus[1] = 237;
    modulus[32] = 127;
    for key in [high_bit, modulus] {
        create_config_fixture(key)
            .expect_err(&mollusk, custom(CustomRingError::InvalidAuditorPubkey));
    }
fn create_config_stores_an_anonymous_ring() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    *fixture.data_mut() = create_config_data_with(auditor_pubkey(4), 1, 1);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config_pda().0)
        .map(|(_, account)| account.clone())
        .expect("config account in result");
    let config = bytemuck::from_bytes::<RingProgramConfig>(&written.data);
    assert_eq!(config.mode(), Some(RingMode::Anonymous));
    assert!(!config.has_legacy_auditor_key());
}

#[test]
fn an_anonymous_flag_above_one_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_config_fixture(auditor_pubkey(4));
    *fixture.data_mut() = create_config_data_with(auditor_pubkey(4), 1, 2);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}
