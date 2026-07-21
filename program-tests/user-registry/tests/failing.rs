mod common;

use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use user_registry_tests::{
    build_register_ix, build_revoke_sync_delegate_ix, build_rotate_sync_delegate_key_ix,
    build_set_merging_enabled_ix, build_set_sync_delegate_ix, test_p256_pubkey,
    user_registry_program_id, TestTransactionResult, UserRegistryTestRig,
};
use zolana_user_registry::error::UserRegistryError;
use zolana_user_registry_interface::{
    instruction::{self, discriminator, RegisterData, SetSyncDelegateData, UpdateKeysData},
    user_record_pda,
};

use common::{funded_keypair, keys, register};

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
fn a_non_owner_cannot_set_a_delegate_for_an_existing_record() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let stranger = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(11));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");
    let ix = instruction::set_sync_delegate(
        record_address,
        stranger.pubkey(),
        SetSyncDelegateData {
            sync_delegate: stranger.pubkey().to_bytes(),
            sync_pubkey: test_p256_pubkey(0x91),
            viewing_pubkey: test_p256_pubkey(0x92),
        },
    );

    assert_registry_error(
        rig.send(ix, &[&stranger]),
        UserRegistryError::InvalidRecordPda,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}

#[test]
fn owner_cannot_rotate_delegate_keys_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let bob = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(12));
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            bob.pubkey(),
            test_p256_pubkey(0xA1),
            test_p256_pubkey(0xA2),
        ),
        &[&owner],
    )
    .expect("set bob");
    rig.send(
        build_rotate_sync_delegate_key_ix(
            &owner.pubkey(),
            &bob.pubkey(),
            test_p256_pubkey(0xA3),
            test_p256_pubkey(0xA4),
        ),
        &[&bob],
    )
    .expect("rotate active delegate");
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before_owner_attempt = rig.svm.get_account(&record_address).expect("record");

    assert_registry_error(
        rig.send(
            build_rotate_sync_delegate_key_ix(
                &owner.pubkey(),
                &owner.pubkey(),
                test_p256_pubkey(0xA5),
                test_p256_pubkey(0xA6),
            ),
            &[&owner],
        ),
        UserRegistryError::InvalidSyncDelegate,
    );
    assert_eq!(
        rig.svm.get_account(&record_address),
        Some(before_owner_attempt)
    );
}

#[test]
fn replaced_delegate_cannot_rotate_keys() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let bob = funded_keypair(&mut rig);
    let carol = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(12));
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            bob.pubkey(),
            test_p256_pubkey(0xA1),
            test_p256_pubkey(0xA2),
        ),
        &[&owner],
    )
    .expect("set bob");
    rig.send(
        build_rotate_sync_delegate_key_ix(
            &owner.pubkey(),
            &bob.pubkey(),
            test_p256_pubkey(0xA3),
            test_p256_pubkey(0xA4),
        ),
        &[&bob],
    )
    .expect("rotate active delegate");
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            carol.pubkey(),
            test_p256_pubkey(0xA7),
            test_p256_pubkey(0xA8),
        ),
        &[&owner],
    )
    .expect("replace bob with carol");

    assert_registry_error(
        rig.send(
            build_rotate_sync_delegate_key_ix(
                &owner.pubkey(),
                &bob.pubkey(),
                test_p256_pubkey(0xA9),
                test_p256_pubkey(0xAA),
            ),
            &[&bob],
        ),
        UserRegistryError::InvalidSyncDelegate,
    );
}

#[test]
fn rotate_rejects_never_set_delegate_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let delegate = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(17));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before_never_set = rig.svm.get_account(&record_address).expect("record");

    assert_registry_error(
        rig.send(
            build_rotate_sync_delegate_key_ix(
                &owner.pubkey(),
                &delegate.pubkey(),
                test_p256_pubkey(0xC1),
                test_p256_pubkey(0xC2),
            ),
            &[&delegate],
        ),
        UserRegistryError::InvalidSyncDelegate,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before_never_set));
}

#[test]
fn rotate_rejects_revoked_delegate_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let delegate = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(17));
    let record_address = user_record_pda(&owner.pubkey()).0;
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            delegate.pubkey(),
            test_p256_pubkey(0xC3),
            test_p256_pubkey(0xC4),
        ),
        &[&owner],
    )
    .expect("set delegate");
    rig.send(
        build_revoke_sync_delegate_ix(&owner.pubkey(), &owner.pubkey()),
        &[&owner],
    )
    .expect("revoke delegate");
    let before_revoked = rig.svm.get_account(&record_address).expect("record");

    assert_registry_error(
        rig.send(
            build_rotate_sync_delegate_key_ix(
                &owner.pubkey(),
                &delegate.pubkey(),
                test_p256_pubkey(0xC5),
                test_p256_pubkey(0xC6),
            ),
            &[&delegate],
        ),
        UserRegistryError::InvalidSyncDelegate,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before_revoked));
}

#[test]
fn revoke_rejects_missing_delegate_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(14));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");

    assert_registry_error(
        rig.send(
            build_revoke_sync_delegate_ix(&owner.pubkey(), &owner.pubkey()),
            &[&owner],
        ),
        UserRegistryError::SyncDelegateNotSet,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}

#[test]
fn revoke_rejects_unauthorized_signer_atomically() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let stranger = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(14));
    let record_address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&record_address).expect("record");

    assert_registry_error(
        rig.send(
            build_revoke_sync_delegate_ix(&owner.pubkey(), &stranger.pubkey()),
            &[&stranger],
        ),
        UserRegistryError::UnauthorizedSigner,
    );
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
