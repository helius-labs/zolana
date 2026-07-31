//! Coverage for the P256 proof of possession that `register` and `update_keys`
//! require whenever the instruction data carries an `owner_p256`.
//!
//! The program reads the proof from the secp256r1 precompile instruction at
//! relative index -1, so when a proof is present the registry instruction sits
//! at transaction index 1 and its errors are reported against that index.

mod common;

use solana_instruction::error::InstructionError;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use user_registry_tests::{
    build_register_ix, build_register_ixs, build_update_keys_ix, build_update_keys_ixs,
    p256_binding_signature, p256_owner_key, TestTransactionResult, UserRegistryTestRig,
};
use zolana_user_registry::error::UserRegistryError;
use zolana_user_registry_interface::user_record_pda;

use common::{funded_keypair, keys, register};

#[track_caller]
fn assert_registry_error_at(result: TestTransactionResult, index: u8, expected: UserRegistryError) {
    let failure = result.expect_err("instruction must fail");
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(index, InstructionError::Custom(expected as u32)),
        "unexpected transaction failure; logs:\n{}",
        failure.meta.pretty_logs(),
    );
}

#[test]
fn register_with_a_valid_p256_proof_stores_the_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(60);
    let key = p256_owner_key();
    let (owner_p256, signature) = p256_binding_signature(&owner.pubkey(), &key);

    rig.send_all(
        &build_register_ixs(
            &owner.pubkey(),
            Some(owner_p256),
            value.nullifier,
            value.viewing,
            Some(signature),
        ),
        &[&owner],
    )
    .expect("register with p256 proof");

    let record = rig.record(&owner.pubkey());
    assert_eq!(record.owner_p256, Some(owner_p256));
    assert_eq!(record.nullifier_pubkey, value.nullifier);
    assert_eq!(record.viewing_pubkey, value.viewing);
    assert_eq!(record.owner, owner.pubkey());
    assert!(!record.merging_enabled);
}

#[test]
fn register_with_an_owner_p256_but_no_proof_is_rejected() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(61);
    let key = p256_owner_key();
    let (owner_p256, _signature) = p256_binding_signature(&owner.pubkey(), &key);

    // Registry instruction alone: nothing precedes it for the program to read.
    assert_registry_error_at(
        rig.send(
            build_register_ix(
                &owner.pubkey(),
                Some(owner_p256),
                value.nullifier,
                value.viewing,
            ),
            &[&owner],
        ),
        0,
        UserRegistryError::MissingP256Proof,
    );
    let (record_address, _bump) = user_record_pda(&owner.pubkey());
    assert_eq!(rig.svm.get_account(&record_address), None);
}

#[test]
fn register_proof_for_a_different_key_is_rejected() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(62);
    let registered = p256_owner_key();
    let attacker = p256_owner_key();
    let (registered_p256, _) = p256_binding_signature(&owner.pubkey(), &registered);
    let (attacker_p256, attacker_signature) = p256_binding_signature(&owner.pubkey(), &attacker);

    // A proof that genuinely establishes possession of the attacker's key, paired
    // with a register naming a key the attacker does not hold. The program pins
    // the precompile's pubkey blob to the instruction data's `owner_p256`.
    let attacker_proof = build_register_ixs(
        &owner.pubkey(),
        Some(attacker_p256),
        value.nullifier,
        value.viewing,
        Some(attacker_signature),
    )
    .swap_remove(0);
    let register_other_key = build_register_ix(
        &owner.pubkey(),
        Some(registered_p256),
        value.nullifier,
        value.viewing,
    );

    assert_registry_error_at(
        rig.send_all(&[attacker_proof, register_other_key], &[&owner]),
        1,
        UserRegistryError::InvalidP256Proof,
    );
    let (record_address, _bump) = user_record_pda(&owner.pubkey());
    assert_eq!(rig.svm.get_account(&record_address), None);
}

#[test]
fn register_proof_bound_to_a_different_owner_is_rejected() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let other_owner = funded_keypair(&mut rig);
    let value = keys(63);
    let key = p256_owner_key();
    let (owner_p256, _) = p256_binding_signature(&owner.pubkey(), &key);
    // Same P256 key, but the signed message binds the other owner's record, so a
    // proof issued for one account cannot be replayed into another's register.
    let (other_p256, other_signature) = p256_binding_signature(&other_owner.pubkey(), &key);
    let foreign_proof = build_register_ixs(
        &other_owner.pubkey(),
        Some(other_p256),
        value.nullifier,
        value.viewing,
        Some(other_signature),
    )
    .swap_remove(0);
    let register_owner = build_register_ix(
        &owner.pubkey(),
        Some(owner_p256),
        value.nullifier,
        value.viewing,
    );

    assert_registry_error_at(
        rig.send_all(&[foreign_proof, register_owner], &[&owner]),
        1,
        UserRegistryError::InvalidP256Proof,
    );
    let (record_address, _bump) = user_record_pda(&owner.pubkey());
    assert_eq!(rig.svm.get_account(&record_address), None);
}

#[test]
fn update_keys_with_a_valid_p256_proof_rebinds_the_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    // Register without a key so this covers the None -> Some rebind.
    let value = keys(64);
    rig.send(
        build_register_ix(&owner.pubkey(), None, value.nullifier, value.viewing),
        &[&owner],
    )
    .expect("register without a p256 key");
    assert_eq!(rig.record(&owner.pubkey()).owner_p256, None);

    let updated = keys(65);
    let key = p256_owner_key();
    let (owner_p256, signature) = p256_binding_signature(&owner.pubkey(), &key);

    rig.send_all(
        &build_update_keys_ixs(
            &owner.pubkey(),
            Some(owner_p256),
            updated.nullifier,
            updated.viewing,
            Some(signature),
        ),
        &[&owner],
    )
    .expect("update keys with p256 proof");

    let record = rig.record(&owner.pubkey());
    assert_eq!(record.owner_p256, Some(owner_p256));
    assert_eq!(record.nullifier_pubkey, updated.nullifier);
    assert_eq!(record.viewing_pubkey, updated.viewing);
}

#[test]
fn update_keys_with_an_owner_p256_but_no_proof_is_rejected() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(66));
    let (record_address, _bump) = user_record_pda(&owner.pubkey());
    let before = rig.svm.get_account(&record_address).expect("record");

    let updated = keys(67);
    let key = p256_owner_key();
    let (owner_p256, _signature) = p256_binding_signature(&owner.pubkey(), &key);

    assert_registry_error_at(
        rig.send(
            build_update_keys_ix(
                &owner.pubkey(),
                Some(owner_p256),
                updated.nullifier,
                updated.viewing,
            ),
            &[&owner],
        ),
        0,
        UserRegistryError::MissingP256Proof,
    );
    assert_eq!(rig.svm.get_account(&record_address), Some(before));
}
