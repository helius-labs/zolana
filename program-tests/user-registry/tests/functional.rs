mod common;

use solana_keypair::Keypair;
use solana_signer::Signer;
use user_registry_tests::{
    build_register_ix, build_set_merge_encryption_ix, build_update_keys_ix,
    user_registry_program_id, UserRecord, UserRegistryTestRig,
};
use zolana_user_registry_interface::{
    instruction::{self, RegisterData},
    user_record_pda, MergeEncryptionScheme,
};

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
    assert_eq!(record.nullifier_pubkey, value.nullifier);
    assert_eq!(record.viewing_pubkey, value.viewing);
    assert_eq!(record.merge_encryption, MergeEncryptionScheme::Disabled);

    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::SIZE);
}

#[test]
fn register_supports_a_prefunded_pda() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let value = keys(2);
    let record_address = user_record_pda(&owner.pubkey()).0;
    rig.fund(&record_address, 1_000_000);

    rig.send(
        build_register_ix(&owner.pubkey(), value.nullifier, value.viewing),
        &[&owner],
    )
    .expect("register over prefunded PDA");

    let record = rig.record(&owner.pubkey());
    assert_eq!(record.nullifier_pubkey, value.nullifier);
    assert_eq!(record.viewing_pubkey, value.viewing);
    assert_eq!(record.owner, owner.pubkey());
    assert_eq!(record.bump, user_record_pda(&owner.pubkey()).1);
    assert_eq!(record.merge_encryption, MergeEncryptionScheme::Disabled);

    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::SIZE);
}

/// A separate payer funds the record's rent, so an owner holding 0 SOL can be
/// registered. The rig's payer covers the transaction fee, so `rent_payer`'s
/// balance drops by exactly the rent.
#[test]
fn register_charges_rent_to_a_separate_payer() {
    let mut rig = UserRegistryTestRig::new();
    let owner = Keypair::new();
    let rent_payer = funded_keypair(&mut rig);
    let value = keys(3);
    let (user_record, bump) = user_record_pda(&owner.pubkey());
    let rent = rig.svm.minimum_balance_for_rent_exemption(UserRecord::SIZE);
    let rent_payer_before = rig
        .svm
        .get_balance(&rent_payer.pubkey())
        .expect("rent payer balance");

    rig.send(
        instruction::register(
            user_record,
            owner.pubkey(),
            rent_payer.pubkey(),
            RegisterData {
                nullifier_pubkey: value.nullifier,
                viewing_pubkey: value.viewing,
            },
        ),
        &[&owner, &rent_payer],
    )
    .expect("register with a separate payer");

    assert_eq!(
        rig.record(&owner.pubkey()),
        UserRecord {
            owner: owner.pubkey(),
            bump,
            nullifier_pubkey: value.nullifier,
            viewing_pubkey: value.viewing,
            merge_encryption: MergeEncryptionScheme::Disabled,
        }
    );
    let account = rig.svm.get_account(&user_record).expect("record account");
    assert_eq!(account.owner, user_registry_program_id());
    assert_eq!(account.data.len(), UserRecord::SIZE);
    assert_eq!(account.lamports, rent);
    assert_eq!(rig.svm.get_balance(&owner.pubkey()).unwrap_or(0), 0);
    let rent_payer_after = rig
        .svm
        .get_balance(&rent_payer.pubkey())
        .expect("rent payer balance");
    assert_eq!(rent_payer_before.checked_sub(rent_payer_after), Some(rent));
}

/// A separate payer covers only the missing rent of a prefunded record.
#[test]
fn register_tops_up_a_prefunded_pda_from_a_separate_payer() {
    let mut rig = UserRegistryTestRig::new();
    let owner = Keypair::new();
    let rent_payer = funded_keypair(&mut rig);
    let value = keys(4);
    let (user_record, bump) = user_record_pda(&owner.pubkey());
    let prefund = 1_000_000;
    rig.fund(&user_record, prefund);
    let rent = rig.svm.minimum_balance_for_rent_exemption(UserRecord::SIZE);
    let rent_payer_before = rig
        .svm
        .get_balance(&rent_payer.pubkey())
        .expect("rent payer balance");
    rig.send(
        instruction::register(
            user_record,
            owner.pubkey(),
            rent_payer.pubkey(),
            RegisterData {
                nullifier_pubkey: value.nullifier,
                viewing_pubkey: value.viewing,
            },
        ),
        &[&owner, &rent_payer],
    )
    .expect("register with a separate payer");

    assert_eq!(
        rig.record(&owner.pubkey()),
        UserRecord {
            owner: owner.pubkey(),
            bump,
            nullifier_pubkey: value.nullifier,
            viewing_pubkey: value.viewing,
            merge_encryption: MergeEncryptionScheme::Disabled,
        }
    );
    assert_eq!(rig.svm.get_balance(&user_record), Some(rent));
    let rent_payer_after = rig
        .svm
        .get_balance(&rent_payer.pubkey())
        .expect("rent payer balance");
    assert_eq!(
        rent_payer_before.checked_sub(rent_payer_after),
        rent.checked_sub(prefund)
    );
}

#[test]
fn update_keys_changes_only_the_viewing_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(6));
    rig.send(
        build_set_merge_encryption_ix(
            &owner.pubkey(),
            &owner.pubkey(),
            MergeEncryptionScheme::PoseidonCtrV1,
        ),
        &[&owner],
    )
    .expect("enable merging");
    let before = rig.record(&owner.pubkey());
    let updated = keys(7);
    rig.send(
        build_update_keys_ix(&owner.pubkey(), keys(6).nullifier, updated.viewing),
        &[&owner],
    )
    .expect("update viewing key");

    let after = rig.record(&owner.pubkey());
    assert_eq!(after.nullifier_pubkey, keys(6).nullifier);
    assert_eq!(after.viewing_pubkey, updated.viewing);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.bump, before.bump);
    assert_eq!(after.merge_encryption, before.merge_encryption);
    let account = rig
        .svm
        .get_account(&user_record_pda(&owner.pubkey()).0)
        .expect("record");
    assert_eq!(account.data.len(), UserRecord::SIZE);
    let body_len = borsh::to_vec(&after).expect("serialized record").len();
    assert_eq!(body_len + UserRecord::DISCRIMINATOR_LEN, UserRecord::SIZE);
}

#[test]
fn owner_can_enable_merging() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(15));

    rig.send(
        build_set_merge_encryption_ix(
            &owner.pubkey(),
            &owner.pubkey(),
            MergeEncryptionScheme::PoseidonCtrV1,
        ),
        &[&owner],
    )
    .expect("enable merging");
    assert_eq!(
        rig.record(&owner.pubkey()).merge_encryption,
        MergeEncryptionScheme::PoseidonCtrV1
    );
}

#[test]
fn owner_can_disable_merging() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(15));
    rig.send(
        build_set_merge_encryption_ix(
            &owner.pubkey(),
            &owner.pubkey(),
            MergeEncryptionScheme::PoseidonCtrV1,
        ),
        &[&owner],
    )
    .expect("enable merging");

    rig.send(
        build_set_merge_encryption_ix(
            &owner.pubkey(),
            &owner.pubkey(),
            MergeEncryptionScheme::Disabled,
        ),
        &[&owner],
    )
    .expect("disable merging");
    assert_eq!(
        rig.record(&owner.pubkey()).merge_encryption,
        MergeEncryptionScheme::Disabled
    );
}
