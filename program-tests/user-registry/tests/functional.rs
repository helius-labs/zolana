mod common;

use solana_signer::Signer;
use user_registry_tests::{
    build_register_ix, build_set_merging_enabled_ix, build_update_keys_ix, test_p256_pubkey,
    user_registry_program_id, UserRecord, UserRegistryTestRig,
};
use zolana_user_registry_interface::user_record_pda;

use common::{funded_keypair, keys, register};

#[test]
fn register_initializes_the_complete_record() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(1);

    register(&mut rig, &owner, value);

    let record = rig.record(&owner.pubkey());
    assert_eq!(record.owner, owner.pubkey());
    assert_eq!(record.bump, user_record_pda(&owner.pubkey()).1);
    assert_eq!(record.owner_p256, Some(value.owner_p256));
    assert_eq!(record.nullifier_pubkey, value.nullifier);
    assert_eq!(record.viewing_pubkey, value.viewing);
    assert!(!record.merging_enabled);

    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::SIZE);
}

#[test]
fn register_supports_a_prefunded_pda_and_an_absent_p256_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(2);
    let record_address = user_record_pda(&owner.pubkey()).0;
    rig.fund(&record_address, 1_000_000);

    rig.send(
        build_register_ix(&owner.pubkey(), None, value.nullifier, value.viewing),
        &[&owner],
    )
    .expect("register over prefunded PDA");

    let record = rig.record(&owner.pubkey());
    assert_eq!(record.owner_p256, None);
    assert_eq!(record.nullifier_pubkey, value.nullifier);
    assert_eq!(record.viewing_pubkey, value.viewing);
    assert_eq!(record.owner, owner.pubkey());
    assert_eq!(record.bump, user_record_pda(&owner.pubkey()).1);
    assert!(!record.merging_enabled);

    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::SIZE);
}

/// Clearing the P256 key (`owner_p256: Some -> None`) shortens the borsh body
/// by the 33-byte key while the account allocation stays fixed at
/// `UserRecord::SIZE`. Main's `write_record` zeroes the whole account before
/// writing, so the vacated tail is all zeros; the record then regrows
/// correctly when a key is registered again.
#[test]
fn update_keys_clears_and_restores_the_p256_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(18);
    register(&mut rig, &owner, value);
    let record_address = user_record_pda(&owner.pubkey()).0;
    let account_before = rig.svm.get_account(&record_address).expect("record");
    let body_before = borsh::to_vec(&rig.record(&owner.pubkey()))
        .expect("serialize pre-update record")
        .len();

    rig.send(
        build_update_keys_ix(&owner.pubkey(), None, value.nullifier, value.viewing),
        &[&owner],
    )
    .expect("clear the P256 key");

    let account = rig.svm.get_account(&record_address).expect("record");
    assert_eq!(
        account.data.len(),
        UserRecord::SIZE,
        "the allocation must not shrink"
    );
    let cleared = rig.record(&owner.pubkey());
    assert_eq!(cleared.owner_p256, None, "re-parsed record is cleared");
    assert_eq!(cleared.nullifier_pubkey, value.nullifier);
    assert_eq!(cleared.viewing_pubkey, value.viewing);
    assert_eq!(cleared.owner, owner.pubkey());

    // The borsh body is exactly 33 bytes (the vacated key) shorter than the
    // pre-update body, and the vacated tail is all zeros: main's
    // `write_record` fills the account before writing.
    let body_len = borsh::to_vec(&cleared)
        .expect("serialize cleared record")
        .len();
    assert_eq!(
        body_len + 33,
        body_before,
        "clearing the key must shorten the serialized body by the key length"
    );
    let needed = UserRecord::DISCRIMINATOR_LEN + body_len;
    assert_eq!(
        account.data.get(needed..),
        Some(&vec![0u8; account_before.data.len() - needed][..]),
        "the vacated tail is zeroed (write_record fills before writing)"
    );

    // None -> Some regrow with a fresh key.
    let regrown_key = test_p256_pubkey(0xD1);
    rig.send(
        build_update_keys_ix(
            &owner.pubkey(),
            Some(regrown_key),
            value.nullifier,
            value.viewing,
        ),
        &[&owner],
    )
    .expect("restore a P256 key");

    let restored = rig.record(&owner.pubkey());
    assert_eq!(restored.owner_p256, Some(regrown_key));
    assert_eq!(restored.nullifier_pubkey, value.nullifier);
    assert_eq!(restored.viewing_pubkey, value.viewing);
    let account = rig.svm.get_account(&record_address).expect("record");
    assert_eq!(
        account.data.len(),
        UserRecord::SIZE,
        "regrowth fits the original allocation"
    );
    let restored_body_len = borsh::to_vec(&restored)
        .expect("serialize restored record")
        .len();
    assert_eq!(
        restored_body_len, body_before,
        "the regrown body matches the original full-key encoding length"
    );
}

#[test]
fn update_keys_changes_only_the_static_keys() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(6));
    rig.send(
        build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true),
        &[&owner],
    )
    .expect("enable merging");
    let before = rig.record(&owner.pubkey());
    let updated = keys(7);

    rig.send(
        build_update_keys_ix(
            &owner.pubkey(),
            Some(updated.owner_p256),
            updated.nullifier,
            updated.viewing,
        ),
        &[&owner],
    )
    .expect("update keys");

    let after = rig.record(&owner.pubkey());
    assert_eq!(after.owner_p256, Some(updated.owner_p256));
    assert_eq!(after.nullifier_pubkey, updated.nullifier);
    assert_eq!(after.viewing_pubkey, updated.viewing);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.bump, before.bump);
    assert_eq!(after.merging_enabled, before.merging_enabled);
}

#[test]
fn owner_can_enable_merging() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(15));

    rig.send(
        build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true),
        &[&owner],
    )
    .expect("enable merging");
    assert!(rig.record(&owner.pubkey()).merging_enabled);
}

#[test]
fn owner_can_disable_merging() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(15));
    rig.send(
        build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), true),
        &[&owner],
    )
    .expect("enable merging");

    rig.send(
        build_set_merging_enabled_ix(&owner.pubkey(), &owner.pubkey(), false),
        &[&owner],
    )
    .expect("disable merging");
    assert!(!rig.record(&owner.pubkey()).merging_enabled);
}
