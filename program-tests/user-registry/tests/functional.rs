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
