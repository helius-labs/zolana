use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use custom_ring_interface::{
    tag, ReadAccessRecord, READER_KEY_ED25519, READER_KEY_P256, READ_ACCESS_RECORD,
};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;

use crate::common::{
    account, auditor_pubkey, config_pda, ed25519_reader, grant_read_access_fixture,
    initialized_config_account, initialized_reader_account, p256_reader, payer, program_id,
    read_access_record_pda, reader, reader_ix_data, rent_recipient, revoke_read_access_fixture,
    setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn grant_read_access_writes_the_record() {
    for key in [reader(), p256_reader()] {
        let (mollusk, _) = setup_mollusk();
        let grant = grant_read_access_fixture(&key);
        let result = mollusk.process_instruction(grant.instruction(), grant.accounts());
        assert_eq!(result.program_result, ProgramResult::Success);

        let (record, bump) = read_access_record_pda(&key);
        let written = result
            .resulting_accounts
            .iter()
            .find(|(key, _)| key == &record)
            .map(|(_, account)| account.clone())
            .expect("read access record in result");
        assert_eq!(written.owner, program_id());
        assert_eq!(written.data.len(), core::mem::size_of::<ReadAccessRecord>());
        assert_eq!(
            bytemuck::from_bytes::<ReadAccessRecord>(&written.data),
            &ReadAccessRecord {
                discriminator: READ_ACCESS_RECORD,
                reader: key,
                bump,
            }
        );

        let revoke = revoke_read_access_fixture(&key);
        let result = mollusk.process_instruction(revoke.instruction(), revoke.accounts());
        assert_eq!(result.program_result, ProgramResult::Success);
    }
}

#[test]
fn grant_of_an_unsignable_key_is_rejected() {
    let mut pda = ed25519_reader(23);
    pda[0] = 2;
    let mut uncompressed = p256_reader();
    uncompressed[1] = 4;
    let mut padded = ed25519_reader(23);
    padded[33] = 1;
    let mut unknown = ed25519_reader(23);
    unknown[0] = 9;
    let mut off_curve = ed25519_reader(23);
    off_curve[1..33].copy_from_slice(config_pda().0.as_ref());
    let mut weak = [0u8; 34];
    weak[0] = READER_KEY_ED25519;
    weak[1] = 1;
    let mut negative_identity = weak;
    negative_identity[32] = 0x80;
    let mut noncanonical = [0xff; 34];
    noncanonical[0] = READER_KEY_ED25519;
    noncanonical[1] = 0xee;
    noncanonical[33] = 0;
    noncanonical[32] = 0x7f;
    let mut reserved = [0u8; 34];
    reserved[0] = READER_KEY_P256;
    reserved[1..].copy_from_slice(&zolana_interface::P_CONST_SEC1);
    let mut mixed_torsion = [0u8; 34];
    mixed_torsion[0] = READER_KEY_ED25519;
    mixed_torsion[1..33].copy_from_slice(
        &(ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes(),
    );
    for key in [
        pda,
        uncompressed,
        padded,
        unknown,
        off_curve,
        weak,
        negative_identity,
        noncanonical,
        reserved,
        mixed_torsion,
    ] {
        let (mollusk, _) = setup_mollusk();
        let mut fixture = grant_read_access_fixture(&reader());
        *fixture.data_mut() = reader_ix_data(tag::GRANT_READ_ACCESS, &key);
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReaderKey));
    }
}

#[test]
fn grant_by_a_non_authority_signer_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn grant_with_an_unsigned_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.unsign("authority");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn grant_before_the_config_exists_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.set_account("config", account(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::ConfigNotInitialized));
}

#[test]
fn grant_into_a_non_canonical_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.substitute(
        "read_access_record",
        read_access_record_pda(&ed25519_reader(67)).0,
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn double_grant_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.set_account("read_access_record", initialized_reader_account(&reader()));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::ReadAccessRecordAlreadyExists),
    );
}

#[test]
fn grant_with_trailing_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.data_mut().push(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn grant_with_truncated_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.data_mut().truncate(16);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn grant_with_a_wrong_system_program_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.substitute("system_program", Pubkey::new_from_array([68; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
}

#[test]
fn revoke_closes_the_record_to_the_rent_recipient() {
    let (mollusk, _) = setup_mollusk();
    let fixture = revoke_read_access_fixture(&reader());
    let (record, _) = read_access_record_pda(&reader());
    let rent = fixture
        .accounts()
        .iter()
        .find(|(key, _)| key == &record)
        .map(|(_, account)| account.lamports)
        .expect("record in fixture");
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let closed = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &record)
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
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn revoke_of_a_mismatched_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    *fixture.data_mut() = reader_ix_data(tag::REVOKE_READ_ACCESS, &ed25519_reader(67));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn revoke_of_a_non_canonical_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.substitute("read_access_record", Pubkey::new_from_array([74; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn revoke_of_a_record_with_a_wrong_bump_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    let mut record = initialized_reader_account(&reader());
    bytemuck::from_bytes_mut::<ReadAccessRecord>(&mut record.data).bump ^= 1;
    fixture.set_account("read_access_record", record);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn revoke_of_an_uninitialized_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.set_account("read_access_record", account(1_000_000));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn revoke_of_a_foreign_owned_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    let mut record = initialized_reader_account(&reader());
    record.owner = Pubkey::new_from_array([69; 32]);
    fixture.set_account("read_access_record", record);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn revoke_with_trailing_data_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.data_mut().push(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn regrant_after_revoke_succeeds() {
    let (mollusk, _) = setup_mollusk();
    let revoke = revoke_read_access_fixture(&reader());
    let result = mollusk.process_instruction(revoke.instruction(), revoke.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);

    let (record, _) = read_access_record_pda(&reader());
    let closed = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &record)
        .map(|(_, account)| account.clone())
        .expect("closed record");
    let mut grant = grant_read_access_fixture(&reader());
    grant.set_account("read_access_record", closed);
    let regrant = mollusk.process_instruction(grant.instruction(), grant.accounts());
    assert_eq!(regrant.program_result, ProgramResult::Success);
}

#[test]
fn grant_with_payer_as_authority_slot_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.substitute("authority", payer());
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn revoke_aimed_at_the_config_account_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.substitute("read_access_record", config_pda().0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn revoke_to_the_read_access_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.substitute("rent_recipient", read_access_record_pda(&reader()).0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidReadAccessRecord));
}

#[test]
fn grant_under_a_config_with_another_authority_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    let other = Pubkey::new_from_array([70; 32]);
    fixture.set_account(
        "config",
        initialized_config_account(other, auditor_pubkey(2)),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn grant_with_an_unsigned_payer_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.unsign("payer");
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}

#[test]
fn grant_into_a_readonly_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.set_writable("read_access_record", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

/// Attacker-donated lamports at the record PDA take the cold creation path.
#[test]
fn donated_lamports_at_the_record_pda_still_grant() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = grant_read_access_fixture(&reader());
    fixture.set_account("read_access_record", account(1));
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &read_access_record_pda(&reader()).0)
        .map(|(_, account)| account.clone())
        .expect("record in result");
    assert_eq!(
        bytemuck::from_bytes::<ReadAccessRecord>(&written.data).discriminator,
        READ_ACCESS_RECORD
    );
}

#[test]
fn revoke_of_a_readonly_record_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.set_writable("read_access_record", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn revoke_into_a_readonly_rent_recipient_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = revoke_read_access_fixture(&reader());
    fixture.set_writable("rent_recipient", false);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}
