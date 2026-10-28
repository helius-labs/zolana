use borsh::to_vec;
use spr_user_registry_interface::{MergeEncryptionScheme, UserRecord};

#[test]
fn size_covers_max_serialized_size() {
    let record = UserRecord {
        owner: [7u8; 32].into(),
        bump: 254,
        nullifier_pubkey: [9u8; 32],
        viewing_pubkey: [4u8; 33],
        merge_encryption: MergeEncryptionScheme::PoseidonCtrV1,
    };
    let body = to_vec(&record).unwrap();
    assert_eq!(UserRecord::DISCRIMINATOR_LEN + body.len(), UserRecord::SIZE);
}
