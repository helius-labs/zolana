mod common;

use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use user_registry_tests::{
    build_register_ix, build_set_merging_enabled_ix, user_registry_program_id,
    TestTransactionResult, UserRegistryTestRig,
};
use zolana_user_registry::error::UserRegistryError;
use zolana_user_registry_interface::{
    instruction::{self, discriminator, RegisterData, UpdateKeysData},
    user_record_pda,
};

use common::{funded_keypair, keys, register};

// NOTE: stays local instead of reusing zolana-test-utils' assert_instruction_error because
// that helper takes zolana_program_test::ProgramTestError, and this crate drives raw LiteSVM
// results (TestTransactionResult) without depending on zolana-program-test/zolana-test-utils.
#[track_caller]
fn assert_error(result: TestTransactionResult, expected: InstructionError) {
    let failure = result.expect_err("instruction must fail");
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(0, expected),
        "unexpected transaction failure; logs:\n{}",
        failure.meta.pretty_logs(),
    );
}

#[track_caller]
fn assert_registry_error(result: TestTransactionResult, expected: UserRegistryError) {
    assert_error(result, InstructionError::Custom(expected as u32));
}

#[test]
fn register_rejects_duplicate_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(3);
    register(&mut rig, &owner, value);
    let record_address = user_record_pda(&owner.pubkey()).0;
    let original = rig.svm.get_account(&record_address).expect("record");

    assert_error(
        rig.send(
            build_register_ix(
                &owner.pubkey(),
                Some(value.owner_p256),
                value.nullifier,
                value.viewing,
            ),
            &[&owner],
        ),
        InstructionError::AccountAlreadyInitialized,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(original));
}

#[test]
fn register_rejects_wrong_pda() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(3);
    let wrong_record = Pubkey::new_unique();
    rig.fund(&wrong_record, 1_000_000);
    let wrong_pda_ix = instruction::register(
        wrong_record,
        owner.pubkey(),
        RegisterData {
            owner_p256: Some(value.owner_p256),
            nullifier_pubkey: value.nullifier,
            viewing_pubkey: value.viewing,
        },
    );

    assert_registry_error(
        rig.send(wrong_pda_ix, &[&owner]),
        UserRegistryError::InvalidRecordPda,
    );
}

#[test]
fn register_requires_owner_signature() {
    let mut rig = UserRegistryTestRig::new();
    let unsigned_owner = funded_keypair(&mut rig);
    let unsigned_value = keys(4);
    let mut unsigned_ix = build_register_ix(
        &unsigned_owner.pubkey(),
        Some(unsigned_value.owner_p256),
        unsigned_value.nullifier,
        unsigned_value.viewing,
    );
    unsigned_ix
        .accounts
        .get_mut(1)
        .expect("owner account")
        .is_signer = false;

    assert_error(
        rig.send(unsigned_ix, &[]),
        InstructionError::MissingRequiredSignature,
    );
}

#[test]
fn register_rejects_invalid_system_program() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let bad_system_owner = funded_keypair(&mut rig);
    let bad_system_value = keys(5);
    let mut bad_system_ix = build_register_ix(
        &bad_system_owner.pubkey(),
        Some(bad_system_value.owner_p256),
        bad_system_value.nullifier,
        bad_system_value.viewing,
    );
    bad_system_ix
        .accounts
        .get_mut(2)
        .expect("system program account")
        .pubkey = owner.pubkey();

    assert_registry_error(
        rig.send(bad_system_ix, &[&bad_system_owner]),
        UserRegistryError::InvalidSystemProgram,
    );
}

#[test]
fn update_keys_rejects_a_non_owner_without_mutating_the_record() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let stranger = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(8));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");
    let updated = keys(9);
    let ix = instruction::update_keys(
        record_address,
        stranger.pubkey(),
        UpdateKeysData {
            owner_p256: Some(updated.owner_p256),
            nullifier_pubkey: updated.nullifier,
            viewing_pubkey: updated.viewing,
        },
    );

    assert_registry_error(rig.send(ix, &[&stranger]), UserRegistryError::OwnerMismatch);
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}

#[test]
fn non_owner_cannot_toggle_merging_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let stranger = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(15));
    rig.send(
        build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true),
        &[&owner],
    )
    .expect("enable merging");
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");

    assert_registry_error(
        rig.send(
            build_set_merging_enabled_ix(&owner.pubkey(), &stranger.pubkey(), false),
            &[&stranger],
        ),
        UserRegistryError::UnauthorizedSigner,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}

/// Unsign the signer meta (index 1: record is 0, signer is 1 in every
/// record-mutating instruction) so the program's `is_signer()` gate is the
/// check that fires.
fn unsign_signer_meta(ix: &mut Instruction) {
    ix.accounts
        .get_mut(1)
        .expect("signer account meta")
        .is_signer = false;
}

#[test]
fn set_merging_enabled_requires_owner_signature() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(24));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");

    let mut ix = build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true);
    unsign_signer_meta(&mut ix);

    assert_error(
        rig.send(ix, &[]),
        InstructionError::MissingRequiredSignature,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}

#[test]
fn update_keys_requires_owner_signature() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(25));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");
    let updated = keys(26);

    let mut ix = instruction::update_keys(
        record_address,
        owner.pubkey(),
        UpdateKeysData {
            owner_p256: Some(updated.owner_p256),
            nullifier_pubkey: updated.nullifier,
            viewing_pubkey: updated.viewing,
        },
    );
    unsign_signer_meta(&mut ix);

    assert_error(
        rig.send(ix, &[]),
        InstructionError::MissingRequiredSignature,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}

#[test]
fn dispatch_rejects_empty_data_exactly() {
    let mut rig = UserRegistryTestRig::new();
    assert_error(
        rig.send(
            Instruction {
                program_id: user_registry_program_id(),
                accounts: vec![],
                data: Vec::new(),
            },
            &[],
        ),
        InstructionError::InvalidInstructionData,
    );
}

#[test]
fn dispatch_rejects_unknown_discriminator_exactly() {
    let mut rig = UserRegistryTestRig::new();
    assert_error(
        rig.send(
            Instruction {
                program_id: user_registry_program_id(),
                accounts: vec![],
                data: vec![u8::MAX],
            },
            &[],
        ),
        InstructionError::InvalidInstructionData,
    );
}

#[test]
fn dispatch_rejects_malformed_register_data_exactly() {
    let mut rig = UserRegistryTestRig::new();
    assert_registry_error(
        rig.send(
            Instruction {
                program_id: user_registry_program_id(),
                accounts: vec![],
                data: vec![discriminator::REGISTER, 1, 2, 3],
            },
            &[],
        ),
        UserRegistryError::InvalidInstructionData,
    );
}

/// Every borsh-parsing dispatch arm rejects a truncated/trailing payload with
/// the exact instruction-data error, before any account is touched. (Main's
/// #167 cleanup removed the three sync-delegate arms; REGISTER,
/// SET_MERGING_ENABLED, and UPDATE_KEYS remain.)
#[test]
fn dispatch_rejects_malformed_payloads_for_every_parsing_arm() {
    let mut rig = UserRegistryTestRig::new();
    for tag in [
        discriminator::SET_MERGING_ENABLED,
        discriminator::UPDATE_KEYS,
    ] {
        assert_registry_error(
            rig.send(
                Instruction {
                    program_id: user_registry_program_id(),
                    accounts: vec![],
                    data: vec![tag, 1, 2, 3],
                },
                &[],
            ),
            UserRegistryError::InvalidInstructionData,
        );
    }
}

/// A record account that is unowned, uninitialized, readonly, or carries a
/// wrong discriminator must be rejected by every record-mutating instruction's
/// loader with the exact record error.
#[test]
fn record_mutation_rejects_invalid_record_accounts() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(34));

    // Unowned: a funded system account in the record slot.
    let unowned = Pubkey::new_unique();
    rig.fund(&unowned, 1_000_000);
    let mut ix = build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true);
    ix.accounts.first_mut().expect("record meta").pubkey = unowned;
    assert_registry_error(
        rig.send(ix, &[&owner]),
        UserRegistryError::InvalidRecordAccount,
    );

    // Uninitialized: registry-owned but zero-length data.
    let uninitialized = Pubkey::new_unique();
    rig.svm
        .set_account(
            uninitialized,
            solana_account::Account {
                lamports: 1_000_000,
                data: Vec::new(),
                owner: user_registry_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write uninitialized record");
    let mut ix = build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true);
    ix.accounts.first_mut().expect("record meta").pubkey = uninitialized;
    assert_registry_error(
        rig.send(ix, &[&owner]),
        UserRegistryError::InvalidRecordAccount,
    );

    // Wrong discriminator: registry-owned with a corrupt first byte.
    let wrong_discriminator = Pubkey::new_unique();
    rig.svm
        .set_account(
            wrong_discriminator,
            solana_account::Account {
                lamports: 1_000_000,
                data: vec![0xAA; 16],
                owner: user_registry_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write wrong-discriminator record");
    let mut ix = build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true);
    ix.accounts.first_mut().expect("record meta").pubkey = wrong_discriminator;
    assert_registry_error(
        rig.send(ix, &[&owner]),
        UserRegistryError::InvalidRecordAccount,
    );

    // Readonly: the real record with the writable flag stripped.
    let mut ix = build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true);
    ix.accounts.first_mut().expect("record meta").is_writable = false;
    assert_registry_error(
        rig.send(ix, &[&owner]),
        UserRegistryError::InvalidRecordAccount,
    );
    assert!(
        !rig.record(&owner.pubkey()).merging_enabled,
        "no rejected mutation may have toggled merging"
    );
}

#[test]
fn register_rejects_readonly_record() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(16);
    let record_address = user_record_pda(&owner.pubkey()).0;
    rig.fund(&record_address, 1_000_000);
    let mut readonly = build_register_ix(
        &owner.pubkey(),
        Some(value.owner_p256),
        value.nullifier,
        value.viewing,
    );
    readonly
        .accounts
        .first_mut()
        .expect("record account")
        .is_writable = false;

    assert_registry_error(
        rig.send(readonly, &[&owner]),
        UserRegistryError::InvalidRecordAccount,
    );
}

// `InstructionError::NotEnoughAccountKeys` is `#[deprecated]` in
// solana-instruction-error, but the runtime still returns it for this shape.
#[allow(deprecated)]
#[test]
fn register_rejects_too_few_accounts() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(16);
    let record_address = user_record_pda(&owner.pubkey()).0;
    rig.fund(&record_address, 1_000_000);
    let data = RegisterData {
        owner_p256: Some(value.owner_p256),
        nullifier_pubkey: value.nullifier,
        viewing_pubkey: value.viewing,
    };
    let mut encoded = vec![discriminator::REGISTER];
    borsh::to_writer(&mut encoded, &data).expect("encode register data");
    let too_few = Instruction {
        program_id: user_registry_program_id(),
        accounts: vec![
            AccountMeta::new(record_address, false),
            AccountMeta::new(owner.pubkey(), true),
        ],
        data: encoded,
    };

    assert_error(
        rig.send(too_few, &[&owner]),
        InstructionError::NotEnoughAccountKeys,
    );
}
