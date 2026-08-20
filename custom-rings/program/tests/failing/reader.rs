use custom_ring_program::{
    error::CustomRingError,
    state::{ReaderRecord, READER_RECORD},
    tag,
};
use mollusk_svm::result::ProgramResult;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{
    account, config_pda, grant_reader_fixture, initialized_reader_account, payer, program_id,
    reader, reader_ix_data, reader_record_pda, rent_recipient, revoke_reader_fixture,
    setup_mollusk, substitute_account,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// Pins the green fixture: without it the negatives below could pass for the
/// wrong reason.
#[test]
fn grant_reader_writes_the_record() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = grant_reader_fixture(&reader());
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_eq!(result.program_result, ProgramResult::Success);

    let (record, bump) = reader_record_pda(&reader());
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &record)
        .map(|(_, account)| account.clone())
        .expect("reader record in result");
    assert_eq!(written.owner, program_id());
    assert_eq!(written.data.len(), ReaderRecord::SIZE);
    assert_eq!(
        bytemuck::from_bytes::<ReaderRecord>(&written.data),
        &ReaderRecord {
            discriminator: READER_RECORD,
            reader: reader().to_bytes(),
            bump,
        }
    );
}

#[test]
fn grant_by_a_non_authority_signer_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = grant_reader_fixture(&reader());
    let impostor = Pubkey::new_from_array([66; 32]);
    substitute_account(&mut instruction, &mut accounts, 1, impostor);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedAuthority),
    );
}

#[test]
fn grant_with_an_unsigned_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = grant_reader_fixture(&reader());
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
fn grant_before_the_config_exists_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = grant_reader_fixture(&reader());
    let (config, _) = config_pda();
    if let Some(entry) = accounts.iter_mut().find(|(key, _)| key == &config) {
        entry.1 = account(0);
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ConfigNotInitialized),
    );
}

/// The record address must be the canonical derivation of the granted key, or
/// one grant could occupy another reader's record address.
#[test]
fn grant_into_a_non_canonical_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = grant_reader_fixture(&reader());
    let other_record = reader_record_pda(&Pubkey::new_from_array([67; 32])).0;
    substitute_account(&mut instruction, &mut accounts, 3, other_record);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidReaderRecord),
    );
}

#[test]
fn double_grant_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = grant_reader_fixture(&reader());
    let (record, _) = reader_record_pda(&reader());
    if let Some(entry) = accounts.iter_mut().find(|(key, _)| key == &record) {
        entry.1 = initialized_reader_account(&reader());
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::ReaderRecordAlreadyExists),
    );
}

#[test]
fn grant_with_trailing_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = grant_reader_fixture(&reader());
    instruction.data.push(0);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

#[test]
fn grant_with_truncated_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = grant_reader_fixture(&reader());
    instruction.data.truncate(16);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

#[test]
fn grant_with_a_wrong_system_program_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = grant_reader_fixture(&reader());
    substitute_account(
        &mut instruction,
        &mut accounts,
        4,
        Pubkey::new_from_array([68; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidSystemProgram),
    );
}

#[test]
fn revoke_closes_the_record_to_the_rent_recipient() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = revoke_reader_fixture(&reader());
    let rent = accounts
        .iter()
        .find(|(key, _)| key == &reader_record_pda(&reader()).0)
        .map(|(_, account)| account.lamports)
        .expect("record in fixture");
    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_eq!(result.program_result, ProgramResult::Success);
    let closed = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &reader_record_pda(&reader()).0)
        .map(|(_, account)| account.clone())
        .expect("record in result");
    assert_eq!((closed.lamports, closed.data.len()), (0, 0));
    let recipient = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &rent_recipient())
        .map(|(_, account)| account.lamports)
        .expect("rent recipient in result");
    assert_eq!(recipient, rent);
}

#[test]
fn revoke_by_a_non_authority_signer_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = revoke_reader_fixture(&reader());
    let impostor = Pubkey::new_from_array([66; 32]);
    substitute_account(&mut instruction, &mut accounts, 0, impostor);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedAuthority),
    );
}

/// The record must belong to the key named in the data, or revoking reader A
/// could close reader B's record.
#[test]
fn revoke_of_a_mismatched_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = revoke_reader_fixture(&reader());
    instruction.data = reader_ix_data(tag::REVOKE_READER, &Pubkey::new_from_array([67; 32]));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidReaderRecord),
    );
}

#[test]
fn revoke_of_an_uninitialized_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = revoke_reader_fixture(&reader());
    let (record, _) = reader_record_pda(&reader());
    if let Some(entry) = accounts.iter_mut().find(|(key, _)| key == &record) {
        entry.1 = account(1_000_000);
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidReaderRecord),
    );
}

#[test]
fn revoke_of_a_foreign_owned_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = revoke_reader_fixture(&reader());
    let (record, _) = reader_record_pda(&reader());
    if let Some(entry) = accounts.iter_mut().find(|(key, _)| key == &record) {
        entry.1.owner = Pubkey::new_from_array([69; 32]);
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidReaderRecord),
    );
}

#[test]
fn revoke_with_trailing_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = revoke_reader_fixture(&reader());
    instruction.data.push(0);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidInstructionData),
    );
}

/// The payer keeps the granted key spendable: a re-grant after a revoke must
/// succeed, so a revoke that leaves state behind would show up here.
#[test]
fn regrant_after_revoke_succeeds() {
    let (mollusk, _) = setup_mollusk();
    let (revoke, accounts) = revoke_reader_fixture(&reader());
    let result = mollusk.process_instruction(&revoke, &accounts);
    assert_eq!(result.program_result, ProgramResult::Success);

    let (grant, mut grant_accounts) = grant_reader_fixture(&reader());
    let (record, _) = reader_record_pda(&reader());
    let closed = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &record)
        .map(|(_, account)| account.clone())
        .expect("closed record");
    if let Some(entry) = grant_accounts.iter_mut().find(|(key, _)| key == &record) {
        entry.1 = closed;
    }
    let regrant = mollusk.process_instruction(&grant, &grant_accounts);
    assert_eq!(regrant.program_result, ProgramResult::Success);
}

/// The payer never stands in for the authority: index 1 is the checked signer
/// even when the payer also signed.
#[test]
fn grant_with_payer_as_authority_slot_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = grant_reader_fixture(&reader());
    substitute_account(&mut instruction, &mut accounts, 1, payer());
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedAuthority),
    );
}

/// A revoke aimed at the config account instead of a record must not close the
/// config: the length check refuses any account that is not a record.
#[test]
fn revoke_aimed_at_the_config_account_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = revoke_reader_fixture(&reader());
    substitute_account(&mut instruction, &mut accounts, 2, config_pda().0);
    accounts.retain(|(key, _)| key != &reader_record_pda(&reader()).0);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidReaderRecord),
    );
}

/// The check compares against the stored authority, not the fixture's: a config
/// naming another key refuses the fixture signer.
#[test]
fn grant_under_a_config_with_another_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = grant_reader_fixture(&reader());
    let (config, _) = config_pda();
    let other = Pubkey::new_from_array([70; 32]);
    if let Some(entry) = accounts.iter_mut().find(|(key, _)| key == &config) {
        entry.1 =
            crate::common::initialized_config_account(other, crate::common::auditor_pubkey(2));
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::UnauthorizedAuthority),
    );
}
