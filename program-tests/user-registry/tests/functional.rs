mod common;

use solana_signer::Signer;
use user_registry_tests::{
    build_register_ix, build_revoke_sync_delegate_ix, build_rotate_sync_delegate_key_ix,
    build_set_merging_enabled_ix, build_set_sync_delegate_ix, build_update_keys_ix,
    test_p256_pubkey, user_registry_program_id, UserRecord, UserRegistryTestRig,
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
    assert_eq!(record.sync_delegate, None);
    assert!(record.entries.is_empty());
    assert!(!record.merging_enabled);
    assert_eq!(record.sender_viewing_pubkey(), value.viewing);

    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::space_for(0));
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
    assert_eq!(record.sync_delegate, None);
    assert!(record.entries.is_empty());
    assert!(!record.merging_enabled);
    assert_eq!(record.sender_viewing_pubkey(), value.viewing);

    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::space_for(0));
}

/// Clearing the P256 key (`owner_p256: Some -> None`) shortens the borsh body
/// by the 33-byte key while the account allocation stays fixed. `write_record`
/// does not zero the vacated tail, so this pins the exact stale bytes left
/// behind and proves an on-chain re-parse still yields the cleared record;
/// the record then regrows correctly when a key is registered again.
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

    // Some -> None.
    rig.send(
        build_update_keys_ix(&owner.pubkey(), None, value.nullifier, value.viewing),
        &[&owner],
    )
    .expect("clear the P256 key");

    let account = rig.svm.get_account(&record_address).expect("record");
    assert_eq!(
        account.data.len(),
        UserRecord::space_for(0),
        "the allocation must not shrink"
    );
    let cleared = rig.record(&owner.pubkey());
    assert_eq!(cleared.owner_p256, None, "re-parsed record is cleared");
    assert_eq!(cleared.nullifier_pubkey, value.nullifier);
    assert_eq!(cleared.viewing_pubkey, value.viewing);
    assert_eq!(cleared.owner, owner.pubkey());

    // The borsh body is exactly 33 bytes (the vacated key) shorter than the
    // pre-update body, and the vacated tail keeps the previous encoding's
    // bytes at those offsets: `write_record` does not zero them.
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
        account_before.data.get(needed..),
        "the vacated tail keeps the pre-update bytes (write_record does not zero)"
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
        UserRecord::space_for(0),
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
    let delegate = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(6));
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            delegate.pubkey(),
            test_p256_pubkey(0x70),
            test_p256_pubkey(0x71),
        ),
        &[&owner],
    )
    .expect("set delegate");
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
    assert_eq!(after.sync_delegate, before.sync_delegate);
    assert_eq!(after.entries, before.entries);
    assert_eq!(after.merging_enabled, before.merging_enabled);
}

#[test]
fn replacing_a_delegate_appends_full_history() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let bob = funded_keypair(&mut rig);
    let carol = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(10));

    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            bob.pubkey(),
            test_p256_pubkey(0x81),
            test_p256_pubkey(0x82),
        ),
        &[&owner],
    )
    .expect("set first delegate");
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            carol.pubkey(),
            test_p256_pubkey(0x83),
            test_p256_pubkey(0x84),
        ),
        &[&owner],
    )
    .expect("replace delegate");

    let record = rig.record(&owner.pubkey());
    assert_eq!(record.sync_delegate, Some(carol.pubkey().to_bytes()));
    assert_eq!(record.entries.len(), 2);
    assert_eq!(
        record.entries.first().expect("first delegate").delegate,
        bob.pubkey().to_bytes()
    );
    assert_eq!(
        record.entries.get(1).expect("second delegate").delegate,
        carol.pubkey().to_bytes()
    );
    assert_eq!(
        record.sender_viewing_pubkey(),
        record
            .entries
            .get(1)
            .expect("second delegate")
            .viewing_pubkey
    );
    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record");
    assert_eq!(account.data.len(), UserRecord::space_for(2));
    assert!(
        account.lamports
            >= rig
                .svm
                .minimum_balance_for_rent_exemption(account.data.len())
    );
}

#[test]
fn active_delegate_can_rotate_keys() {
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
    let after_rotation = rig.record(&owner.pubkey());
    assert_eq!(after_rotation.sync_delegate, Some(bob.pubkey().to_bytes()));
    assert_eq!(after_rotation.entries.len(), 2);
    assert!(after_rotation
        .entries
        .iter()
        .all(|entry| entry.delegate == bob.pubkey().to_bytes()));
    let rotated = after_rotation
        .entries
        .last()
        .expect("rotated delegate entry");
    assert_eq!(rotated.sync_pubkey, test_p256_pubkey(0xA3));
    assert_eq!(rotated.viewing_pubkey, test_p256_pubkey(0xA4));
    assert_eq!(
        after_rotation.sender_viewing_pubkey(),
        test_p256_pubkey(0xA4)
    );
}

#[test]
fn active_delegate_can_revoke_itself_while_preserving_history() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let delegate = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(13));
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            delegate.pubkey(),
            test_p256_pubkey(0xB1),
            test_p256_pubkey(0xB2),
        ),
        &[&owner],
    )
    .expect("set delegate");

    rig.send(
        build_revoke_sync_delegate_ix(&owner.pubkey(), &delegate.pubkey()),
        &[&delegate],
    )
    .expect("delegate revokes itself");
    let revoked = rig.record(&owner.pubkey());
    assert_eq!(revoked.sync_delegate, None);
    assert_eq!(revoked.entries.len(), 1);
    assert_eq!(revoked.sender_viewing_pubkey(), revoked.viewing_pubkey);
}

#[test]
fn owner_can_revoke_delegate_while_preserving_history() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let delegate = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(13));
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            delegate.pubkey(),
            test_p256_pubkey(0xB1),
            test_p256_pubkey(0xB2),
        ),
        &[&owner],
    )
    .expect("set delegate");
    rig.send(
        build_revoke_sync_delegate_ix(&owner.pubkey(), &delegate.pubkey()),
        &[&delegate],
    )
    .expect("delegate revokes itself");
    rig.send(
        build_set_sync_delegate_ix(
            &owner.pubkey(),
            delegate.pubkey(),
            test_p256_pubkey(0xB3),
            test_p256_pubkey(0xB4),
        ),
        &[&owner],
    )
    .expect("reappoint delegate");

    rig.send(
        build_revoke_sync_delegate_ix(&owner.pubkey(), &owner.pubkey()),
        &[&owner],
    )
    .expect("owner revokes delegate");
    let owner_revoked = rig.record(&owner.pubkey());
    assert_eq!(owner_revoked.sync_delegate, None);
    assert_eq!(owner_revoked.entries.len(), 2);
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
