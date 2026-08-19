use custom_ring_program::{
    error::CustomRingError,
    state::{
        RingProgramConfig, ASSETS_ANY, MAX_ALLOWED_ASSETS, RING_PROGRAM_CONFIG, WITHDRAWALS_OPEN,
    },
    tag,
};
use mollusk_svm::result::ProgramResult;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    auditor_pubkey, authority, config_pda, create_config_data, create_config_fixture,
    create_config_fixture_deployed_by, initialized_config_account, program_data_account,
    program_data_pda, program_id, setup_mollusk, substitute_account,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// Pins the green fixture: without it the negatives below could pass for the
/// wrong reason (a fixture that never reaches the checked code).
#[test]
fn create_config_writes_the_config_account() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = create_config_fixture(auditor_pubkey(2));
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_eq!(result.program_result, ProgramResult::Success);

    let (config, bump) = config_pda();
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config)
        .map(|(_, account)| account.clone())
        .expect("config account in result");
    assert_eq!(written.owner, program_id());
    assert_eq!(written.data.len(), RingProgramConfig::SIZE);
    let authority = instruction
        .accounts
        .get(1)
        .expect("authority meta")
        .pubkey
        .to_bytes();
    assert_eq!(
        bytemuck::from_bytes::<RingProgramConfig>(&written.data),
        &RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority: pinocchio::Address::new_from_array(authority),
            auditor_pubkey: auditor_pubkey(2),
            bump,
            withdrawals: WITHDRAWALS_OPEN,
            asset_policy: ASSETS_ANY,
            allowed_assets_len: 0,
            allowed_assets: [[0u8; 32]; MAX_ALLOWED_ASSETS],
        },
        "a fresh config starts with the open policy"
    );
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = create_config_fixture(auditor_pubkey(2));
    instruction.data = vec![tag::CREATE_CONFIG, 1, 2, 3];
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

#[test]
fn trailing_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = create_config_fixture(auditor_pubkey(2));
    instruction.data = create_config_data(auditor_pubkey(2));
    instruction.data.push(0);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
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
    let (mut instruction, accounts) = create_config_fixture(auditor_pubkey(2));
    instruction
        .accounts
        .first_mut()
        .expect("payer meta")
        .is_signer = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn unsigned_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = create_config_fixture(auditor_pubkey(2));
    instruction
        .accounts
        .get_mut(1)
        .expect("authority meta")
        .is_signer = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn readonly_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = create_config_fixture(auditor_pubkey(2));
    instruction
        .accounts
        .get_mut(2)
        .expect("config meta")
        .is_writable = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn wrong_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = create_config_fixture(auditor_pubkey(2));
    substitute_account(
        &mut instruction,
        &mut accounts,
        3,
        Pubkey::new_from_array([31; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidSystemProgram),
    );
}

#[test]
fn uncompressed_auditor_pubkey_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    // 0x04 is the SEC1 uncompressed prefix: the stored key must be compressed.
    let (instruction, accounts) = create_config_fixture(auditor_pubkey(4));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidAuditorPubkey),
    );
}

#[test]
fn zero_prefix_auditor_pubkey_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = create_config_fixture(auditor_pubkey(0));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidAuditorPubkey),
    );
}

#[test]
fn non_canonical_config_pda_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = create_config_fixture(auditor_pubkey(2));
    substitute_account(
        &mut instruction,
        &mut accounts,
        2,
        Pubkey::new_from_array([41; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidConfigPda),
    );
}

#[test]
fn double_initialization_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = create_config_fixture(auditor_pubkey(2));
    let (config, _) = config_pda();
    replace_account(
        &mut accounts,
        config,
        initialized_config_account(authority(), auditor_pubkey(2)),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ConfigAlreadyInitialized),
    );
}

#[test]
fn foreign_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let other = Pubkey::new_from_array([42; 32]);
    let (instruction, accounts) =
        create_config_fixture_deployed_by(auditor_pubkey(2), Some(&other));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedInitializer),
    );
}

/// An immutable deployment names no authority, so the first caller wins.
#[test]
fn unset_upgrade_authority_skips_the_gate() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = create_config_fixture_deployed_by(auditor_pubkey(2), None);
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_eq!(result.program_result, ProgramResult::Success);
}

/// solana-test-validator `--bpf-program` writes a zeroed authority.
#[test]
fn zeroed_upgrade_authority_skips_the_gate() {
    let (mollusk, _) = setup_mollusk();
    let zero = Pubkey::new_from_array([0; 32]);
    let (instruction, accounts) = create_config_fixture_deployed_by(auditor_pubkey(2), Some(&zero));
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_eq!(result.program_result, ProgramResult::Success);
}

/// A `ProgramData` account at any other address, even one naming the
/// authority, does not satisfy the gate.
#[test]
fn foreign_program_data_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = create_config_fixture(auditor_pubkey(2));
    let impostor = Pubkey::new_from_array([43; 32]);
    substitute_account(&mut instruction, &mut accounts, 5, impostor);
    replace_account(
        &mut accounts,
        impostor,
        program_data_account(Some(&authority())),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedInitializer),
    );
}

/// The gate reads the ring program's own account, never a caller-chosen one.
#[test]
fn foreign_program_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = create_config_fixture(auditor_pubkey(2));
    substitute_account(
        &mut instruction,
        &mut accounts,
        4,
        Pubkey::new_from_array([44; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedInitializer),
    );
}

/// Truncated loader state fails closed rather than skipping the check.
#[test]
fn truncated_program_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = create_config_fixture(auditor_pubkey(2));
    let mut truncated = program_data_account(Some(&authority()));
    truncated.data.truncate(8);
    replace_account(&mut accounts, program_data_pda(), truncated);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedInitializer),
    );
}

fn replace_account(accounts: &mut [(Pubkey, Account)], key: Pubkey, replacement: Account) {
    let slot = accounts
        .iter_mut()
        .find(|(candidate, _)| candidate == &key)
        .expect("account present in fixture");
    slot.1 = replacement;
}
